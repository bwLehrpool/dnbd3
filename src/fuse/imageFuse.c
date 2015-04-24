/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2007 Miklos Szeredi <miklos@szeredi.hu>
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 *
 * Changed by Stephan Schwaer
 * */

#define FUSE_USE_VERSION 30
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
/* for socket */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "protocol.h"
#include "serialize.h"
/* for printing uint */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "imageHelper.h"

/* variables for socket */
int sock = -1;
int n;

char* server_adress = NULL;
int portno = -1;
char* image_Name = NULL;
char* imagePathName = NULL;
uint16_t rid;
uint8_t flags8;
char buffer[1000];
static uint64_t imageSize;
/* Debug/Benchmark variables */
bool useDebug = false;
bool useLog = false;
log_info logInfo;
uint8_t printCount = 0;

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

static int image_getattr(const char *path, struct stat *stbuf)
{ 
  int res = 0;
  memset(stbuf, 0, sizeof(struct stat));
  if (strcmp(path, "/") == 0) {
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
  } else if (strcmp(path, imagePathName) == 0) {
    stbuf->st_mode = S_IFREG | 0755;
    stbuf->st_nlink = 1;
    stbuf->st_size = imageSize;
  } else
    res = -ENOENT;
  return res;
}

static int image_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
    off_t offset, struct fuse_file_info *fi)
{
  (void) offset;
  (void) fi;
  if (strcmp(path, "/") != 0)
    return -ENOENT;
  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);
  filler(buf, imagePathName + 1, NULL, 0);
  return 0;
}

static int image_open(const char *path, struct fuse_file_info *fi)
{
  if (strcmp(path, imagePathName) != 0)
    return -ENOENT;
  if ((fi->flags & 3) != O_RDONLY)
    return -EACCES;
  return 0;
}

static int image_read(const char *path, char *buf, size_t size, off_t offset,
    struct fuse_file_info *fi)
{
  size_t len;
  /* buffer for throwing away unwanted messages. */
  char tBuf[100];

  (void) fi;
  if(strcmp(path, imagePathName) != 0)
    return -ENOENT;
  len = imageSize;
  if (offset < len) {
    if (offset + size > len)
      size = len - offset;

get_block:
    /* seek inside the image */
    if(!dnbd3_get_block(sock, offset, size, offset)){
      printf("[ERROR] Get block error!\n");}
    else {
      printf("Get block success!\n");
    }

    /* count the requested blocks */
    uint64_t startBlock = offset / (4096);
    uint64_t endBlock = (offset + size - 1) / (4096);

    printf("StartBlockRequest: %"PRIu64"\n", startBlock);
    printf("EndBlockRequest: %"PRIu64"\n", endBlock);
    
    if(useDebug) {
      for (; startBlock <= endBlock; startBlock++){
        logInfo.blockRequestCount[startBlock] += 1;
      }
    }

    dnbd3_reply_t reply;

    /*see if the received package is a requested block, throw away if not */
    while(true){
      if(!dnbd3_get_reply(sock, &reply)){
        printf("[ERROR] Reply error\n");
        
        /* Try to reconnect after reply error */
        printf("Reconnecting!\n");
        sock = connect_to_server(&server_adress, &portno);
        
        if (sock == -1){
          printf("[ERROR] Connection Error!");
          exit(1);
        }

        printf("Selecting image ");

        bzero(buffer,256);
        rid = 0;
        flags8 = 0;
        serialized_buffer_t sbuffer;
        uint16_t protocol_version;   
        char *name;
        uint16_t rrid;

        if(dnbd3_select_image(sock, image_Name, rid, flags8) != 1){
            printf("- Error\n");
          } else {printf("- Success\n");
        }

          if(!dnbd3_select_image_reply(&sbuffer, sock, &protocol_version, &name, &rrid, &imageSize)) {
            printf("Error reading reply\n");
            exit(1);
          } else {printf("Reply successful\n");
        }

        printf("Protocol version: %i, Image: %s, RevisionID: %i, Size: %i MiB\n",(int) protocol_version, name, (int) rrid,(int) (imageSize/(1024*1024)));
        goto get_block;

      } else {
        printf("Reply success\n");
      }
      if(reply.cmd == CMD_ERROR) {
        printf("Got a CMD_ERROR!\n");
        exit(1);
      }
      if(reply.cmd != CMD_GET_BLOCK) {
        printf("Received block isn't a wanted block, throwing it away...\n");
        int tDone = 0;
        int todo;
        while(tDone < reply.size){
          todo = reply.size - tDone > 100 ? 100: reply.size - tDone;
            
          n = read(sock, tBuf, todo);
          if (n <= 0) {
            if(n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            printf("[ERROR] Errno %i and %i\n",errno, n);
            exit(1);
          }
          tDone += n ;
        }
        continue;
      }
      break;
    }

    printf("Payloadsize: %i\n",(int) reply.size);
    printf("Offset: %"PRIu64"\n", reply.handle);

    if(size != reply.size){
        printf("Size: %i, reply.size: %i!\n",(int) size,(int) reply.size);
        exit(1);
    }
    /* read the data block data from received package */
    int done = 0;
    while (done < size ){
      n = read(sock, buf + done, size - done);
      if (n <= 0) {
        if(n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        printf("[ERROR] Error: %i and %i\n",errno, n);
        exit(1);
      }
      done += n;
      /* for benchmarking */
      logInfo.receivedBytes += n;
    }
  } else
    size = 0;
  printf("Received bytes: %i MiB\n",(int) (logInfo.receivedBytes/(1024*1024)));

  /* logfile stuff */
  if( useLog ){
    if (printCount == 0){
      printLog(&logInfo);
    }
    printCount = printCount + 1 % 100;
  }
  return size;
}

/* close the connection */
void image_destroy(void* private_data){
  if ( useLog ){
    printLog(&logInfo);
  }
  if (close(sock) != 0) { 
      printf("error closing file.\n");
      exit(-1);
    }
  free(imagePathName);
  return;
}

/* map the implemented fuse operations */
static struct fuse_operations image_oper = {
  .getattr = image_getattr,
  .readdir = image_readdir,
  .open = image_open,
  .read = image_read,
  .destroy = image_destroy,
};

int main (int argc, char *argv[])
{
  char* mountPoint = NULL;
  int opt;
  bool testOpt = false;

  if(argc == 1 ||strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "--usage") == 0 ){
exit_usage:
    printf("Usage: %s [-l] [-d] [-t] -m <mountpoint> -s <serverAdress> -p <port> -i <imageName>\n", argv[0]);
    printf("    -l: creates a logfile log.txt at program path\n");
    printf("    -d: fuse debug mode\n");
    printf("    -t: use hardcoded server, port and image for testing\n");
    exit(EXIT_FAILURE);
  }

  while((opt = getopt(argc,argv,"m:s:p:i:tdl")) != -1){
    switch(opt) {
      case 'm':
        mountPoint = optarg;
        break;
      case 's':
        server_adress = optarg;
        break;
      case 'p':
        portno = atoi(optarg);
        break;
      case 'i':
        image_Name = optarg;
        break;
      case 't':
        testOpt = true;
        break;
      case 'd':
        useDebug = true;
        break;
      case 'l':
        useLog = true;
        useDebug = true;
        break;
      default:
        goto exit_usage;
    }
  }

  if(testOpt){
    /* values for testing. */
    server_adress = "132.230.4.1";
    portno = 5003;
    image_Name = "windows7-umwelt.vmdk";
    useLog = true;
  }

  if(server_adress == NULL || portno == -1 || image_Name == NULL || mountPoint == NULL){
    goto exit_usage;
  }

  int arg_count = 5;
  if (useDebug){
    arg_count++;
  }
  char * args[6] = {"foo", "-o", "ro,allow_other", "-s", mountPoint, "-d"};

  sock = connect_to_server(&server_adress, &portno);
  
  if (sock == -1){
    printf("[ERROR] Connection Error!");
    exit(1);
  }

  printf("Selecting image ");

  bzero(buffer,256);
  rid = 0;
  flags8 = 0;

  serialized_buffer_t sbuffer;
  uint16_t protocol_version;   
  char *name;
  uint16_t rrid;

  if(dnbd3_select_image(sock, image_Name, rid, flags8) != 1){
      printf("- Error\n");
    } else {printf("- Success\n");
  }

    if(!dnbd3_select_image_reply(&sbuffer, sock, &protocol_version, &name, &rrid, &imageSize)) {
      printf("Error reading reply\n");
      exit(1);
    } else {printf("Reply successful\n");
  }

  printf("Protocol version: %i, Image: %s, RevisionID: %i, Size: %i MiB\n",(int) protocol_version, name, (int) rrid,(int) (imageSize/(1024*1024)));

  /* fix name of image if it contains '/' */
  int len = strlen(image_Name) - 1;
  bool fixName = false;
  for(; len >= 0; len--){
    if(image_Name[len] == '/'){
      fixName = true;
      break;
    }
  }
  if( fixName) {
    memmove(image_Name, image_Name + len + 1, strlen(image_Name) - len);
    printf("image_Name: %s\n", image_Name);
  }


  char * str1 = "/";
  char * tmpStr = (char *) malloc(1 + strlen(str1) + strlen(image_Name));
  strcpy(tmpStr, str1);
  strcat(tmpStr, image_Name);
  imagePathName = tmpStr;
  
  /* initialize benchmark variables */
  logInfo.receivedBytes = 0;
  logInfo.imageSize = imageSize;
  logInfo.imageBlockCount = imageSize % 4096 == 0 ? imageSize/(4096) : imageSize/(4096) + 1;

  uint8_t tmpShrt[logInfo.imageBlockCount];
  uint64_t i = 0;
  if ( useLog ){
    for(; i < logInfo.imageBlockCount; i++){
      tmpShrt[i] = 0;
    }
  }

  logInfo.blockRequestCount = tmpShrt;

  printf("ImagePathName: %s\n",imagePathName);
  return fuse_main(arg_count, args, &image_oper, NULL);
}


