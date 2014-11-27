/* 
 * Common header for UDP based FTP client
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <time.h>

#define DEBUG            0
#define DEBUG_PRINT      1
#define SEQ_NUM_SIZE     4
#define MAX_BUF_SIZE     1024
#define TCP_SEND_SIZE    1024
#define BYTES_RW         MAX_BUF_SIZE + SEQ_NUM_SIZE
#define TCP_PORT         35450

#define TRUE         1
#define FALSE        0

void
error (const char *msg)
{
  perror (msg);
  exit (1);
}

void
gen_checksum (char *filename, unsigned char *digest)
{
  MD5_CTX mdContext;
  int fd, bytes;
  unsigned char fdata[1024];

  fd = open (filename, O_RDONLY);
  if (fd < 0) {
    error ("File can't be opened");
  }

  MD5_Init (&mdContext);

  while ((bytes = read (fd, fdata, sizeof (fdata))) != 0) {
    MD5_Update (&mdContext, fdata, bytes);
  }

  MD5_Final (digest, &mdContext);
  close (fd);
}

char *
get_time (void)
{
  time_t now;
  struct tm *timeinfo;
  time (&now);
  timeinfo = localtime (&now);
  return asctime (timeinfo);
}

#define PUT_UINT32(buf, val)                        \
    do {                                            \
        (*((buf) + 0)) = (val & 0xFF000000) >> 24;  \
        (*((buf) + 1)) = (val & 0x00FF0000) >> 16;  \
        (*((buf) + 2)) = (val & 0x0000FF00) >> 8;   \
        (*((buf) + 3)) = (val & 0x000000FF);        \
    } while (0)

#define GET_UINT32(buf)                         \
    ((*((uint8_t *) buf + 0) << 24)  |          \
     (*((uint8_t *) buf + 1) << 16)  |          \
     (*((uint8_t *) buf + 2) << 8)   |          \
     (*((uint8_t *) buf + 3)))


int
get_file_size (char *filename)
{
  FILE *fp;
  int sz;

  fp = fopen (filename, "r");
  if (fp == NULL) {
    error ("Error opening file");
  }

  fseek (fp, 0L, SEEK_END);
  sz = ftell (fp);
  fclose (fp);
  return sz;
}

#endif
