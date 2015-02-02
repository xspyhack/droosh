#define PCRE_STATIC //
#include <stdio.h>
#include <stdlib.h>
#include <direct.h>
#include <windows.h> 
#include <io.h>
#include <sys/stat.h>
#include <time.h>
#include "pcre.h"
#include "cJSON.h"

#pragma comment(lib,"pcre.lib")


#define FILE_COUNT_MAX_SET 10  //maximum allow file in the dropbox
#define SINGLE_FILE_MAX_SIZE_SET 157286000  //single file maximum size(byte), it must be < 300(Mb)
const char CONFIG_FILE[] = "droosh.ini"; 

char API_REQUEST_TOKEN_URL[] = "https://api.dropbox.com/1/oauth/request_token";
char API_USER_AUTH_URL[] = "https://www2.dropbox.com/1/oauth/authorize";
char API_ACCESS_TOKEN_URL[] = "https://api.dropbox.com/1/oauth/access_token";
char API_UPLOAD_URL[] = "https://api-content.dropbox.com/1/files_put/dropbox";
char API_DOWNLOAD_URL[] = "https://api-content.dropbox.com/1/files/dropbox";
char API_DELETE_URL[] = "https://api.dropbox.com/1/fileops/delete";
char API_INFO_URL[] = "https://api.dropbox.com/1/account/info";
char API_METADATA_URL[] = "https://api.dropbox.com/1/metadata";
char APP_CREATE_URL[] = "https://www2.dropbox.com/developers/apps";
char TOKEN_RESPONSE_FILE[] = "resp_token.txt";

const char *error;
int erroffset;
#define OVECCOUNT 9  /* should be a multiple of 3 */
int  ovector[OVECCOUNT]; 

char RESPONSE_FILE[] = "resp.txt";
char APPKEY[50];
char APPSECRET[50];
char OAUTH_ACCESS_TOKEN_SECRET[50];
char OAUTH_ACCESS_TOKEN[50];
char OAUTH_TOKEN_SECRET[50];
char OAUTH_TOKEN[50];
char FILE_SRC[100];
char FILE_DST[100];
char DIR_SRC[_MAX_PATH];
char DIR_DST[_MAX_PATH];
char FILE_PATH[100];
char COMMAND_STRING[500];
time_t ltime;
bool bSilence = false;
bool bDir = false;
static int FILE_COUNT = 0;
static int DIR_COUNT = 0;

void upload_init(int argc, char **argv);
void simple_upload(char src[100], char dst[100]);
void chunked_upload(int size);
void download_init(int argc, char **argv);
bool download(char src[100], char dst[100]);
void list_init(char **argv);
void list(char dir_dst[_MAX_PATH], bool flag);
void del_init(char **argv);
bool del(char dst[100]);
void free_quota();
void json_parse(char *text, bool flag);
void json_file_read(char *filename, bool flag);
int file_size(char *filename);
void find_file(char *path);
bool check_response(char *filename);
void load_config(const char valueName[], char *valueStore, const char tmpConfig[]);
void usage(int argc, char **argv);
void get_token_value(char tokenSecret[50], char token[50]);
void setup();


int main(int argc, char **argv)
{
	time(&ltime);
	srand(ltime);

	//checking configuration file
	if ((_access(CONFIG_FILE, 0)) == -1)
	{
		setup();
		return 1;
	}

	//CHECKING PARAMS VALUES
	if (argc < 3 || argc > 6)
	{
		usage(argc, argv);
	}
	if (!stricmp(argv[1], "upload"))
	{
		upload_init(argc, argv);
	}
	else if (!stricmp(argv[1], "download"))
	{
		download_init(argc, argv);
	}
	else if (!stricmp(argv[1], "list"))
	{
		list_init(argv);
	}
	else if (!stricmp(argv[1], "delete"))
	{
		del_init(argv);
	}
	else
	{
		usage(argc, argv);
	}

	//CHECKING FOR AUTH FILE
	if ((_access( CONFIG_FILE, 0 )) != -1 ){

		char tmpConfig[50];
		FILE *fp = fopen(CONFIG_FILE, "rb");
		if (fp == NULL)
		{
			printf("Read configuration file error.\n");
			exit(1);
		}
		fgets(tmpConfig, 50, fp);
		load_config("APPKEY", APPKEY, tmpConfig);
		fgets(tmpConfig, 50, fp);
		load_config("APPSECRET", APPSECRET, tmpConfig);
		fgets(tmpConfig, 50, fp);
		load_config("OAUTH_ACCESS_TOKEN", OAUTH_ACCESS_TOKEN, tmpConfig);
		fgets(tmpConfig, 50, fp);
		load_config("OAUTH_ACCESS_TOKEN_SECRET", OAUTH_ACCESS_TOKEN_SECRET, tmpConfig);
		fclose(fp);

		/*
		ifstream config_file(CONFIG_FILE);
		char tmpConfig[50];
		config_file>>tmpConfig;
		load_config("APPKEY", APPKEY, tmpConfig);
		config_file>>tmpConfig;
		load_config("APPSECRET", APPSECRET, tmpConfig);
		config_file>>tmpConfig;
		load_config("OAUTH_ACCESS_TOKEN", OAUTH_ACCESS_TOKEN, tmpConfig);
		config_file>>tmpConfig;
		load_config("OAUTH_ACCESS_TOKEN_SECRET", OAUTH_ACCESS_TOKEN_SECRET, tmpConfig);
		config_file.close();
		*/
	}

	//COMMAND EXECUTION
	if (!stricmp(argv[1], "upload"))
	{
		//check src is dir
		if (bDir)
		{
			long Handle;
			int count = 0;
			struct _finddata_t fileInfo;
			char file_path[_MAX_PATH];
			sprintf(file_path, "%s\\*.*", DIR_DST);
			if((Handle = _findfirst(file_path, &fileInfo)) == -1L)
			{
				printf("No file in this path, please check!\n");
				return 0;
			}
			else
			{
				list("/", false);
				while( _findnext(Handle,  &fileInfo) == 0)
				{
					//wait for download/delete
					while (FILE_COUNT >= FILE_COUNT_MAX_SET)
					{
						printf("Waiting...\n");
						Sleep(5000);
						list("/", false);
						continue;
					}
					if (!stricmp(fileInfo.name, ".."))
						continue;
					else
					{
						sprintf(FILE_SRC, "%s\\%s", DIR_SRC, fileInfo.name);  //the full path
						memset(FILE_DST, 0, sizeof(FILE_DST));
						strcpy(FILE_DST, fileInfo.name);
						simple_upload(FILE_SRC, FILE_DST);
						list("/", false);
						count++;
					}
				}
				_findclose(Handle);
			}
			printf("Upload all %d files success.\n\n", count);
			list("/", true);
			return 0;
		}

		//check file size
		int size = file_size(FILE_SRC);
		printf("File size: %d Bytes.\n", size);
		if (size >= SINGLE_FILE_MAX_SIZE_SET)
		{
			//If the file is greater than 150Mb, the chunked_upload API will be used
			printf("This file is greater than 150Mb, the chunked_upload API will be used.\n");
			chunked_upload(size);
		}
		else
		{
			simple_upload(FILE_SRC, FILE_DST);
		}
	}
	else if (!stricmp(argv[1], "download"))
	{
		//check src is dir
		char temp[100];
		if (bDir)
		{
			while (true)
			{
				list("/", false);
				if (FILE_COUNT > 0)
				{
					memset(temp, 0, sizeof(temp));
					sprintf(temp, "%s\\%s", DIR_DST, FILE_PATH);
					if (download(FILE_PATH, temp))
						del(FILE_PATH);
				}
				Sleep(20000);
			}
		}
		else
		{
			//memset(temp, 0, sizeof(temp));
			//sprintf(temp, "/%s", FILE_SRC);
			download(temp, FILE_DST);
		}
	}
	else if (!stricmp(argv[1], "list"))
	{
		list(DIR_DST, true);
	}
	else if (!stricmp(argv[1], "delete"))
	{
		del(FILE_DST);
	}
	else if (!stricmp(argv[1], "free"))
	{
		free_quota();
	}

	return 0;
}

void upload_init(int argc, char **argv)
{
	printf("The single file size must < 300 Mb.\n");
	memset(FILE_SRC, 0, sizeof(FILE_SRC));
	strcpy(FILE_SRC, argv[2]);
	switch (argc)
	{
	case 3:
		if (!strcmp(argv[2], "-d") || !stricmp(argv[2], "-d"))
		{
			printf("Must specify the source file which you want to upload.\n\n");
			usage(argc, argv);
			exit(1);
		}
		memcpy(FILE_DST, FILE_SRC, sizeof(FILE_SRC));
		break;
	case 4:
		//bSilence = true;
		if (!strcmp(argv[2], "./") && !strcmp(argv[3], "/"))
		{
			printf("The source file or the destination file is a directory,\n");
			printf("if you want to upload all files in specify directory,\n");
			printf("you should add option [-d]. Or you should specity a file, not a directory.");
			usage(argc, argv);
			exit(1);
		}
		else if (!stricmp(argv[3], "-s"))
		{
			bSilence = true;
			memset(FILE_DST, 0, sizeof(FILE_DST));
			memcpy(FILE_DST, FILE_SRC, sizeof(FILE_SRC));
		}
		else if (!stricmp(argv[3], "-d"))
		{
			memset(DIR_SRC, 0, sizeof(DIR_SRC));
			if (!stricmp(argv[2], "./"))
			{
				_getcwd(DIR_SRC, sizeof(DIR_SRC));
			}
			else
			{
				strcpy(DIR_SRC, argv[2]);
			}
			bDir = true;
			//memset(FILE_DST, 0, sizeof(FILE_DST));
			//memcpy(FILE_DST, FILE_SRC, sizeof(FILE_SRC));
		}
		else
		{
			memset(FILE_DST, 0, sizeof(FILE_DST));
			strcpy(FILE_DST, argv[3]);
		}
		break;
	case 5:
		if (!strcmp(argv[2], "./") && !strcmp(argv[3], "/"))
		{
			printf("The source file or the destination file is a directory,\n");
			printf("if you want to upload all files in specify directory,\n");
			printf("you should add option [-d]. Or you should specity a file, not a directory.");
			usage(argc, argv);
			exit(1);
		}
		else if (!stricmp(argv[4], "-d"))
		{
			memset(DIR_SRC, 0, sizeof(DIR_SRC));
			if (!stricmp(argv[2], "./"))
			{
				_getcwd(DIR_SRC, sizeof(DIR_SRC));
			}
			else
			{
				strcpy(DIR_SRC, argv[2]);
			}
			//find_file(buf);
			bDir = true;
		}
		else if (!stricmp(argv[4], "-s"))
		{
			bSilence = true;
			memset(FILE_DST, 0, sizeof(FILE_DST));
			strcpy(FILE_DST, argv[3]);
		}
		else
		{
			usage(argc, argv);
			exit(1);
		}
		break;
	case 6:
		bSilence = true;
		memset(DIR_SRC, 0, sizeof(DIR_SRC));
		if (!stricmp(argv[2], "./"))
		{
			_getcwd(DIR_SRC, sizeof(DIR_SRC));
		}
		else
		{
			strcpy(DIR_SRC, argv[2]);
		}
		bDir = true;

		//memset(FILE_DST, 0, sizeof(FILE_DST));
		//strcpy(FILE_DST, argv[3]);
	}

	//Checking FILE_SRC
	if ((_access(FILE_SRC, 0)) == -1)
	{
		printf("Please specify a valid source file!\n");
		exit(1);
	}
}

void simple_upload(char src[100], char dst[100])
{
	printf("*******************************************************************************\n");
	printf(" Uploading file [%s] -> <%s> ...", src, dst);
	time(&ltime);
	memset(COMMAND_STRING, 0, sizeof(COMMAND_STRING));
	if (!bSilence)
	{
		sprintf(COMMAND_STRING,"curl.exe --progress-bar -k -i -o %s --upload-file \"%s\" \"%s/%s?"
			"oauth_consumer_key=%s&oauth_token=%s&oauth_signature_method=PLAINTEXT&oauth_signature=%s%%26%s&"
			"oauth_timestamp=%ld&oauth_nonce=%d\"", RESPONSE_FILE, src, API_UPLOAD_URL, dst,
			APPKEY, OAUTH_ACCESS_TOKEN, APPSECRET, OAUTH_ACCESS_TOKEN_SECRET, ltime, rand());
	}else
	{
		sprintf(COMMAND_STRING,"curl.exe -s --show-error -k -i -o %s --upload-file \"%s\" \"%s/%s?"
			"oauth_consumer_key=%s&oauth_token=%s&oauth_signature_method=PLAINTEXT&oauth_signature=%s%%26%s&"
			"oauth_timestamp=%ld&oauth_nonce=%d\"", RESPONSE_FILE, src, API_UPLOAD_URL, dst,
			APPKEY, OAUTH_ACCESS_TOKEN, APPSECRET, OAUTH_ACCESS_TOKEN_SECRET, ltime, rand());
	}

	system(COMMAND_STRING);
	printf(" [Done.]\n");
	check_response(RESPONSE_FILE);
	//char outResp[50];
	//sprintf(outResp,"type %s", RESPONSE_FILE);
	//system(outResp);
	remove(RESPONSE_FILE);
}

void chunked_upload(int size)
{
	int ofset = 0;
	char upload_id[] = "";
	int upload_error = 0;
	char chunk_params[] = "";
	printf("Implement later.");

	/*
	while (ofset != size)
	{
		int ofset_mb = ofset / 1024 / 1024;
		
		//create the chunk

	}
	*/
}

void download_init(int argc, char **argv)
{
	memset(FILE_SRC, 0, sizeof(FILE_SRC));
	strcpy(FILE_SRC, argv[2]);
	switch (argc)
	{
	case 3:
		memcpy(FILE_DST, FILE_SRC, sizeof(FILE_SRC));
		break;
	case 4:
		//bSilence = true;
		if (!stricmp(argv[2], "/") && !stricmp(argv[3], "./"))
		{
			usage(argc, argv);
			exit(1);
		}
		else if (!stricmp(argv[3], "-s"))
		{
			bSilence = true;
			memset(FILE_DST, 0, sizeof(FILE_DST));
			memcpy(FILE_DST, FILE_SRC, sizeof(FILE_SRC));
		}
		else if (!stricmp(argv[3], "-d"))
		{
			memset(DIR_DST, 0, sizeof(DIR_DST));
			_getcwd(DIR_DST, sizeof(DIR_DST));
			//find_file(buf);
			bDir = true;
		}
		else
		{
			memset(FILE_DST, 0, sizeof(FILE_DST));
			strcpy(FILE_DST, argv[3]);
		}
		break;
	case 5:
		if (!stricmp(argv[4], "-d"))
		{
			memset(DIR_DST, 0, sizeof(DIR_DST));
			if (!stricmp(argv[3], "./"))
			{
				_getcwd(DIR_DST, sizeof(DIR_DST));
			}
			else
			{
				strcpy(DIR_DST, argv[3]);
			}
			//find_file(buf);
			bDir = true;
		}
		else if (!stricmp(argv[4], "-s"))
		{
			bSilence = true;
			if (!stricmp(argv[2], "./") || !stricmp(argv[3], "/"))
			{
				printf("The source file or the destination file is a directory,\n");
				printf("if you want to upload all files in specify directory,\n");
				printf("you should add option [-d]. Or you should specity a file, not a directory.");
				usage(argc, argv);
				exit(1);
			}
			memset(FILE_DST, 0, sizeof(FILE_DST));
			strcpy(FILE_DST, argv[3]);
		}
		else
		{
			usage(argc, argv);
			exit(1);
		}
		break;
	case 6:
		bSilence = true;
		memset(DIR_DST, 0, sizeof(DIR_DST));
		if (!stricmp(argv[3], "./"))
		{
			_getcwd(DIR_DST, sizeof(DIR_DST));
		}
		else
		{
			strcpy(DIR_DST, argv[3]);
		}
		bDir = true;
	}

	//Checking FILE_DST
	if ((_access(FILE_DST, 0)) != -1)
	{
		printf("Skipping already existing file [%s]!\n", FILE_DST);
		exit(1);
	}
}

bool download(char src[100], char dst[100])
{
	printf("*******************************************************************************\n");
	printf(" Downloading file <%s> -> [%s] ...", src, dst);
	time(&ltime);
	memset(COMMAND_STRING, 0, sizeof(COMMAND_STRING));
	if (!bSilence)
	{
		sprintf(COMMAND_STRING, "curl.exe --progress-bar -k -D %s -o %s \"%s/%s?"
			"oauth_consumer_key=%s&oauth_token=%s&oauth_signature_method=PLAINTEXT&oauth_signature=%s%%26%s&"
			"oauth_timestamp=%ld&oauth_nonce=%d\"", RESPONSE_FILE, dst, API_DOWNLOAD_URL, src,
			APPKEY, OAUTH_ACCESS_TOKEN, APPSECRET, OAUTH_ACCESS_TOKEN_SECRET, ltime, rand());
	}
	else
	{
		sprintf(COMMAND_STRING, "curl.exe -s --show-error -k -D %s -o %s \"%s/%s?"
			"oauth_consumer_key=%s&oauth_token=%s&oauth_signature_method=PLAINTEXT&oauth_signature=%s%%26%s&"
			"oauth_timestamp=%ld&oauth_nonce=%d\"", RESPONSE_FILE, dst, API_DOWNLOAD_URL, src,
			APPKEY, OAUTH_ACCESS_TOKEN, APPSECRET, OAUTH_ACCESS_TOKEN_SECRET, ltime, rand());
	}

	system(COMMAND_STRING);
	printf(" [Done.]\n");
	bool ret = check_response(RESPONSE_FILE);
	//char outResp[50];
	//sprintf(outResp, "type %s", RESPONSE_FILE);
	//system(outResp);
	remove(RESPONSE_FILE);

	return ret;
}

void list_init(char **argv)
{
	memset(DIR_DST, 0, sizeof(DIR_DST));
	strcpy(DIR_DST, argv[2]);
}

void list(char dir_dst[_MAX_PATH], bool flag)
{
	FILE_COUNT = 0;
	DIR_COUNT = 0;

	printf("*******************************************************************************\n");
	printf(" Listing dir <%s> ...", dir_dst);
	time(&ltime);
	memset(COMMAND_STRING, 0, sizeof(COMMAND_STRING));

	sprintf(COMMAND_STRING, "curl.exe -s --show-error --globoff -k -i -o \"%s\" \"%s/dropbox/%s?"
		"oauth_consumer_key=%s&oauth_token=%s&oauth_signature_method=PLAINTEXT&oauth_signature=%s%%26%s&"
		"oauth_timestamp=%ld&oauth_nonce=%d\"", RESPONSE_FILE, API_METADATA_URL, dir_dst,
		APPKEY, OAUTH_ACCESS_TOKEN, APPSECRET, OAUTH_ACCESS_TOKEN_SECRET, ltime, rand());

	system(COMMAND_STRING);
	printf(" [Done.]\n");
	json_file_read(RESPONSE_FILE, flag);
	check_response(RESPONSE_FILE);
	//char outResp[50];
	//sprintf(outResp, "type %s", RESPONSE_FILE);
	//system(outResp);
	remove(RESPONSE_FILE);
}

void del_init(char **argv)
{
	memset(FILE_DST, 0, sizeof(FILE_DST));
	strcpy(FILE_DST, argv[2]);
}

bool del(char dst[100])
{
	printf("*******************************************************************************\n");
	printf(" Deleting file <%s> ...", dst);
	time(&ltime);
	memset(COMMAND_STRING, 0, sizeof(COMMAND_STRING));

	sprintf(COMMAND_STRING, "curl.exe -s --show-error --globoff -k -i -o \"%s\" --data \""
		"oauth_consumer_key=%s&oauth_token=%s&oauth_signature_method=PLAINTEXT&oauth_signature=%s%%26%s&"
		"oauth_timestamp=%ld&oauth_nonce=%d&root=dropbox&path=%s\"" " \"%s\"", RESPONSE_FILE,
		APPKEY, OAUTH_ACCESS_TOKEN, APPSECRET, OAUTH_ACCESS_TOKEN_SECRET, ltime, rand(), dst, API_DELETE_URL);

	system(COMMAND_STRING);
	printf(" [Done.]\n");
	bool ret = check_response(RESPONSE_FILE);
	//char outResp[50];
	//sprintf(outResp, "type %s", RESPONSE_FILE);
	//system(outResp);
	remove(RESPONSE_FILE);

	return ret;
}

void free_quota()
{
}

/* Parse text to JSON, then render back to text, and print! */
void json_parse(char *text, bool flag)
{
	//char *out;
	cJSON *json;
	json = cJSON_Parse(text);
	if (!json)
	{
		printf("Error before: [%s]\n", cJSON_GetErrorPtr());
	}
	else
	{
		cJSON* jsonArr = NULL;
		jsonArr = cJSON_GetObjectItem(json, "contents");
		if (jsonArr)
		{
			int nSize = cJSON_GetArraySize(jsonArr);
			for (int i = 0; i < nSize; i++)
			{
				cJSON *jsonItem = cJSON_GetArrayItem(jsonArr, i);
				if (jsonItem)
				{
					int is_dir = cJSON_GetObjectItem(jsonItem, "is_dir")->valueint;
					char *buf = cJSON_GetObjectItem(jsonItem, "path")->valuestring;
					if (flag)
					{
						printf("path: %-35s", buf);
						printf("size: %-10s", cJSON_GetObjectItem(jsonItem, "size")->valuestring);
						printf("is_dir: %-12d\n", is_dir);
					}
					if (!is_dir)
					{
						FILE_COUNT++;
						memset(FILE_PATH, 0, sizeof(FILE_PATH));
						strcpy(FILE_PATH, buf+1);
					}
					else DIR_COUNT++;
				}
			}
		}/*
		out = cJSON_Print(json);
		cJSON_Delete(json);
		printf("%s\n", out);
		free(out);*/
	}
	printf(" %d files.\n", FILE_COUNT);
	printf(" %d dirs.\n", DIR_COUNT);
}

/* Read a file, parse, render back, etc. */
void json_file_read(char *filename, bool flag)
{
	FILE *fp = fopen(filename, "r+b");
	if (fp == NULL)
	{
		printf("Can't open the file [%s].\n", filename);
		return;
	}

	fseek(fp, 0, SEEK_END);
	long len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char *data = (char *)malloc(len + 1);
	char temp[2];
	int pos = 0;
	do
	{
		memset(temp, 0, 2);
		int res = fread(temp, 1, 1, fp);
		if (strcmp(temp, "{") == 0)
		{
			break;
		}
		pos += res;
	} while (pos < len);

	fseek(fp, pos - 1, 0);
	fread(data, 1, len - pos + 1, fp);
	fclose(fp);
	json_parse(data, flag);
	free(data);
}

//get file size
int file_size(char *filename)
{
	struct stat temp;
	stat(filename, &temp);
	return temp.st_size;
}

//find file in path
void find_file(char *path)
{
	long Handle;
	struct _finddata_t fileInfo;
	char file_path[_MAX_PATH];
	sprintf(file_path, "%s\\*.*", path);
	if((Handle = _findfirst(file_path, &fileInfo)) == -1L)
		printf("No file in this path, please check!\n");
	else
	{
		printf("%s\n", fileInfo.name);
		while( _findnext(Handle,  &fileInfo) == 0)
			printf("%s\n", fileInfo.name);
		_findclose(Handle);
	}
}

bool check_response(char *filename)
{
	FILE *fp = fopen(filename, "r+b");
	if (fp == NULL)
	{
		printf("Can't open the file [%s].\n", filename);
		return true;  //if can't open the file to check response, it will return default value true;
	}

	char *data = (char *)malloc(25);
	fread(data, 1, 25, fp);
	fclose(fp);

	pcre *re;
	const char REG_PATTERN[] = "^HTTP/1.1 (100|200) (OK|Continue)";  //pcre
	re = pcre_compile(REG_PATTERN, 0, &error, &erroffset, NULL);
	if (re == NULL)
	{
		printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
		return false;
	}
	int rc = pcre_exec(re, NULL, data, strlen(data), 0, 0, ovector, OVECCOUNT);
	if (rc < 0)
	{
		printf(" [Cmd excute failed! -.-]\n");
		return false;
	}
	else
		printf(" [Cmd excute success! -_^]\n");
	free(data);

	return true;
}

void load_config(const char valueName[], char *valueStore, const char tmpConfig[])
{
	pcre *re;
	const char REG_PATTERN[] =  ".*:(.*)";  //pcre
	re = pcre_compile(REG_PATTERN, 0, &error, &erroffset, NULL);
	if (re == NULL) {
        printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);  
        return;  
    }  
	int rc = pcre_exec(re, NULL, tmpConfig, strlen(tmpConfig), 0, 0, ovector, OVECCOUNT);
	if (rc < 0) {
		if (rc == PCRE_ERROR_NOMATCH) 
			printf("Can't find %s value in config file! Please check your the droosh.ini\n", valueName);  
		else printf("Find %s error %d\n", valueName, rc);  
		pcre_free(re);  
		exit(0);
		return;  
	}
	memcpy(valueStore, tmpConfig + ovector[2], ovector[3] - ovector[2]);
	pcre_free(re);
}

void get_token_value(char tokenSecret[50], char token[50])
{
	if( (_access( TOKEN_RESPONSE_FILE, 0 )) == -1 ){
		printf("Response file not found!\n");
		return;
	}
	FILE *fp = fopen(TOKEN_RESPONSE_FILE, "rb");
	//ifstream config_file(TOKEN_RESPONSE_FILE);
	char tmpLine[1000];
	
	pcre *re, *re2;
	const char TOKEN_SECRET_PATTERN[] = "oauth_token_secret=([a-z A-Z 0-9]*).*";
	const char TOKEN_PATTERN[] = ".*oauth_token=([a-z A-Z 0-9]*)";
	re = pcre_compile(TOKEN_SECRET_PATTERN, 0, &error,&erroffset, NULL);
	re2 = pcre_compile(TOKEN_PATTERN, 0, &error, &erroffset, NULL);
	if (re == NULL || re2 == NULL) {
        printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);  
        return;  
    }
	while (!feof(fp))
	{
		//config_file>>tmpLine;
		fgets(tmpLine, 1000, fp);
		int rc = pcre_exec(re, NULL, tmpLine, strlen(tmpLine), 0, 0, ovector, OVECCOUNT);
		if (rc > 0)
		{
			memcpy(tokenSecret, tmpLine + ovector[2], ovector[3] - ovector[2]);  //OAUTH_TOKEN_SECRET
			pcre_exec(re2, NULL, tmpLine, strlen(tmpLine), 0, 0, ovector, OVECCOUNT); 
			memcpy(token, tmpLine+ovector[2], ovector[3] - ovector[2]);  //OAUTH_TOKEN
			printf("OK\n");
			pcre_free(re);
			return;
		}
	}
	printf(" FAILED!\n\n Verify your App key and secret...\n\n");
	remove(TOKEN_RESPONSE_FILE);
//	exit(1);
}

//Setup
void setup()
{//NEW SETUP.../**/
	printf("\n This is the first time you run this program.\n");
	printf(" Please open this URL from your Browser, and access using your account:\n\n -> %s\n", APP_CREATE_URL);
	printf("\n If you haven't already done, click \"Create an App\" and fill in the\n");
	printf(" form with the following data:\n\n");
	printf(" App name: MyUploader%ld%ld\n", rand(), rand());
	printf(" Description: What do you want...\n");
	printf(" Access level: Full Dropbox\n\n");
	printf(" Now, click on the \"Create\" button.\n\n");
	printf(" When your new App is successfully created, please insert the\n");
	printf(" App Key and App Secret:\n\n");
	
	//Getting the app key and secret from the user
	while (true){
		printf(" # App key: ");
		scanf("%s", APPKEY);
		printf(" # App secret: ");
		scanf("%s", APPSECRET);
		
		printf("\n > App key is %s and App secret is %s, it's ok? [y/n]", APPKEY, APPSECRET);
		fflush(stdin);
		char answer = getchar();
		if (answer == 'y' || answer == '\n')
			break;
	}
	
	//TOKEN REQUESTS
	printf("\n > Token request... ");
	time(&ltime);
	memset(COMMAND_STRING, 0, sizeof(COMMAND_STRING));
	sprintf(COMMAND_STRING, "curl.exe -s --show-error -k -i -o %s --data \"oauth_consumer_key=%s"
		"&oauth_signature_method=PLAINTEXT&oauth_signature=%s%%26&oauth_timestamp=%ld&oauth_nonce=%ld\" \"%s\"",
		TOKEN_RESPONSE_FILE, APPKEY, APPSECRET, ltime, rand(), API_REQUEST_TOKEN_URL);
	system(COMMAND_STRING);
	memset(OAUTH_TOKEN, 0, sizeof(OAUTH_TOKEN));
	memset(OAUTH_TOKEN_SECRET, 0, sizeof(OAUTH_TOKEN_SECRET));
	get_token_value(OAUTH_TOKEN_SECRET, OAUTH_TOKEN);  //get token value
	if (strlen(OAUTH_TOKEN_SECRET) == 0 || strlen(OAUTH_TOKEN) == 0) exit(1);

	while (true)
	{
		//#USER AUTH
		printf("\n Please visit this URL from your Browser, and allow Dropbox Uploader\n");
		printf("to access your DropBox account:\n\n --> %s?oauth_token=%s\n", API_USER_AUTH_URL, OAUTH_TOKEN);
		printf("\nPress enter when done...\n");

		fflush(stdin);
		getchar();
		
		//#API_ACCESS_TOKEN_URL
		printf(" > Access Token request... ");
		time(&ltime);
		memset(COMMAND_STRING, 0, sizeof(COMMAND_STRING));
		sprintf(COMMAND_STRING,"curl.exe -s --show-error -k -i -o %s --data \"oauth_consumer_key=%s"
			"&oauth_token=%s&oauth_signature_method=PLAINTEXT&oauth_signature=%s%%26%s&oauth_timestamp=%ld&oauth_nonce=%ld\" \"%s\"",
			TOKEN_RESPONSE_FILE, APPKEY, OAUTH_TOKEN, APPSECRET, OAUTH_TOKEN_SECRET, ltime, rand(), API_ACCESS_TOKEN_URL);
		system(COMMAND_STRING);
		memset(OAUTH_ACCESS_TOKEN_SECRET, 0, sizeof(OAUTH_ACCESS_TOKEN_SECRET));
		memset(OAUTH_ACCESS_TOKEN, 0, sizeof(OAUTH_ACCESS_TOKEN));
		get_token_value(OAUTH_ACCESS_TOKEN_SECRET, OAUTH_ACCESS_TOKEN);
		if (strlen(OAUTH_ACCESS_TOKEN) != 0 && strlen(OAUTH_ACCESS_TOKEN_SECRET) != 0)
		{
			//#Saving data
			FILE *fp = fopen(CONFIG_FILE, "wb");
			if (fp != NULL)
			{
				if (fwrite("APPKEY:", strlen("APPKEY"), 1, fp) != 1) printf("Write file error.\n");
				if (fwrite(&APPKEY, strlen(APPKEY), 1, fp) != 1) printf("Write file error.\n");
				if (fwrite("\r\nAPPSECRET:", strlen("\r\nAPPSECRET:"), 1, fp) != 1) printf("Write file error.\n");
				if (fwrite(&APPSECRET, strlen(APPSECRET), 1, fp) != 1) printf("Write file error.\n");
				if (fwrite("\r\nOAUTH_ACCESS_TOKEN:", strlen("\r\nOAUTH_ACCESS_TOKEN:"), 1, fp) != 1) printf("Write file error.\n");
				if (fwrite(&OAUTH_ACCESS_TOKEN, strlen(OAUTH_ACCESS_TOKEN), 1, fp) != 1) printf("Write file error.\n");
				if (fwrite("\r\nOAUTH_ACCESS_TOKEN_SECRET::", strlen("\r\nOAUTH_ACCESS_TOKEN_SECRET:"), 1, fp) != 1) printf("Write file error.\n");
				if (fwrite(&OAUTH_ACCESS_TOKEN_SECRET, strlen(OAUTH_ACCESS_TOKEN_SECRET), 1, fp) != 1) printf("Write file error.\n");
			}
			else
				printf("Can't open configuration file [%s].\n", CONFIG_FILE);
			fclose(fp);
			/*
			ofstream outConfig(CONFIG_FILE);
			if(outConfig.is_open())
			{
				outConfig<<"APPKEY:"<<APPKEY<<endl;
				outConfig<<"APPSECRET:"<<APPSECRET<<endl;
				outConfig<<"OAUTH_ACCESS_TOKEN:"<<OAUTH_ACCESS_TOKEN<<endl;
				outConfig<<"OAUTH_ACCESS_TOKEN_SECRET:"<<OAUTH_ACCESS_TOKEN_SECRET<<endl;
				outConfig.close();
			}*/
			printf("\n Setup completed!\n");
			break; 
		}
	}

	remove(TOKEN_RESPONSE_FILE);
}

//USAGE
void usage(int argc, char **argv)
{
	printf("Usage: %s COMMAND [Options]...\n", argv[0]);
	printf("\nCommands:\n");
	printf("\t upload   [LOCAL_FILE/DIR]   <REMOTE_FILE/DIR> [-d]\n");
	printf("\t download <REMOTE_FILE/DIR>  [LOCAL_FILE/DIR] [-d]\n");
	printf("\t move     <REMOTE_FILE/DIR>  <REMOTE_FILE/DIR>\n");
	printf("\t copy     <REMOTE_FILE/DIR>  <REMOTE_FILE/DIR>\n");
	printf("\t delete   <REMOTE_FILE/DIR>\n");
	printf("\t list     <REMOTE_DIR>\n");
	printf("\t share    <REMOTE_FILE>\n");
	printf("\t info\n");
	printf("\t unlink\n");

	printf("\nOptions:\n");
	printf("\t -s       silent mode\n");
	printf("\t -d       when src/dst is a directory.\n");

	printf("\nFor more info and examples, please see the README file.\n\n");

	exit(0);// 1
}