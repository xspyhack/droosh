Droosh is a tool which can be used to upload and download files and more from Dropbox, an online file sharing, synchronization and backup service.

It's written in C/C++ language and only needs cURL (CLI).

USAGE:
======

Usage: droosh.exe COMMAND [PARAMETERS]...

[%%]: Required param
<%%>: Optional param

Commands:
  upload [LOCAL_FILE] <REMOTE_FILE>
  //Upload local file to remote Dropbox folder

  download [REMOTE_FILE] <LOCAL_FILE>
  //Download file from Dropbox to local folder

  delete [REMOTE_FILE]
  //Remove a remote file from Dropbox

  list [REMOTE_DIR]
  //List the remote directory from Dropbox

Examples:
  droosh.exe upload ./localfile remotefile
  droosh.exe upload ./localfile
  droosh.exe download remotefile
  droosh.exe delete remotefile
  droosh.exe list remote_dir
  
Tips:
  It's sure that droosh.exe and cURL.exe must in the same directory.
