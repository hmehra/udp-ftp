/* 
 * A simple FTP server in the internet domain using UDP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include "common.h"
#include <assert.h>

int interation = 0;

static uint32_t g_file_size = 0;
static uint32_t g_chunks = 0;
static int g_fd = 0;

static int udp_sockfd = 0, tcp_sockfd = 0, tcp_newsockfd = 0;
static uint32_t g_tx_chunks = 0;
static uint32_t g_dropped_chunks = 0;
int read_comp = 0;
int *drop_chunks = NULL;
char *drop_buffer;
unsigned int transfer_port;

unsigned char digest[MD5_DIGEST_LENGTH];
static int start_flag = FALSE;
static int end_flag = FALSE;
static int send_end_flag = FALSE;

static int transmission_end_flag = FALSE;
static int drop_packet_flag = FALSE;

struct sockaddr_in cli_addr_udp, cli_addr_tcp;;
struct sockaddr_in serv_addr_udp;

char filename[MAX_BUF_SIZE];

static uint32_t chunks_rx = 0;
static uint32_t file_size = 0;
static uint32_t num_chunks = 0;
static int prev_read = MAX_BUF_SIZE;
static int recv_complete_flag = FALSE;
static int all_received = TRUE;
static int g_fd;

char *file_data;
static int iteration = 0;

uint8_t *recv_pkts;


void
retransmit_dropped_packets (void)
{
  int counter = 0, retval;
  int recv_bytes = 0;
  FILE *fp = fopen (filename, "r");
  char buffer[BYTES_RW];

  while (counter <= g_dropped_chunks) {
    fseek (fp, drop_chunks[counter] * MAX_BUF_SIZE, SEEK_SET);
    recv_bytes = fread ((buffer + SEQ_NUM_SIZE), 1, MAX_BUF_SIZE, fp);
    PUT_UINT32 (&buffer[0], drop_chunks[counter]);
    retval = fcntl (udp_sockfd, F_SETFL,
		    fcntl (udp_sockfd, F_GETFL) & ~O_NONBLOCK);
    if (retval != 0) {
      fprintf (stdout, "FNCTL error");
    }
    retval = sendto (udp_sockfd, buffer, (recv_bytes + SEQ_NUM_SIZE), 0,
		     (struct sockaddr *) &cli_addr_udp,
		     sizeof (cli_addr_udp));
    if (retval < 0) {
      error ("ERROR retransmitting dropped packets");
    }
    retval = fcntl (udp_sockfd, F_SETFL,
		    fcntl (udp_sockfd, F_GETFL) | O_NONBLOCK);
    if (retval != 0) {
      fprintf (stdout, "FNCTL error");
    }
    g_tx_chunks++;
    memset (buffer, 0, sizeof (buffer));
    counter++;
  }

  /* Make TCP Wait */
  send_end_flag = TRUE;

#if DEBUG_PRINT
  fprintf (stdout, "Retransmissed Packets - %d\n", counter);
#endif //DEBUG

  fclose (fp);
}


void
handle_control_packets (int fd)
{
  char file_size_str[16], chunk_str[16];
  char buffer[MAX_BUF_SIZE];
  int retval, counter = 0;

  memset (buffer, 0, sizeof (buffer));
  memset (file_size_str, 0, sizeof (file_size_str));
  memset (chunk_str, 0, sizeof (chunk_str));

  snprintf (file_size_str, sizeof (file_size_str), "%u", g_file_size);
  snprintf (chunk_str, sizeof (chunk_str), "%u", g_chunks);

  strcat (buffer, file_size_str);
  strcat (buffer, " ");
  strcat (buffer, chunk_str);

  /* Send file size */
  retval = write (fd, buffer, sizeof (buffer));
  if (retval < 0) {
    error ("Error file_size not sent");
  }
}

void *
SendChunk (void *arg)
{
  int retval, recv_bytes;
  char buffer[BYTES_RW];
  int local_send = 0;

  memset (cli_addr_udp.sin_zero, 0, sizeof (cli_addr_udp.sin_zero));
  cli_addr_udp.sin_family = AF_INET;
  cli_addr_udp.sin_addr.s_addr = cli_addr_tcp.sin_addr.s_addr;
  cli_addr_udp.sin_port = htons (transfer_port);

  memset (buffer, 0, sizeof (buffer));
  while (start_flag == FALSE);

  while ((recv_bytes =
	  read (g_fd, (buffer + SEQ_NUM_SIZE), MAX_BUF_SIZE)) != 0) {
    if (recv_bytes < 0) {
      error ("Cannot read from file");
    }
    PUT_UINT32 (&buffer[0], g_tx_chunks);

    retval = sendto (udp_sockfd, buffer, (recv_bytes + SEQ_NUM_SIZE), 0,
		     (struct sockaddr *) &cli_addr_udp,
		     sizeof (cli_addr_udp));
    if (retval < 0) {
      error ("ERROR could not send the first time");
    }
    g_tx_chunks++;
    local_send++;
    memset (buffer, 0, sizeof (buffer));
  }
  send_end_flag = TRUE;

#if DEBUG_PRINT
  fprintf (stdout, "UDP Server sent chunks in first time %d\n", local_send);
#endif //DEBUG
}


void *
drop_packets (void *arg)
{
  char recv_buffer[MAX_BUF_SIZE];
  int p = 0, j = 0, retval;
  ssize_t recv_bytes = 0;
  socklen_t servlen = sizeof (struct sockaddr_in);

  retval = fcntl (udp_sockfd, F_SETFL,
		  fcntl (udp_sockfd, F_GETFL) | O_NONBLOCK);
  if (retval != 0) {
    fprintf (stdout, "FNCTL error");
  }
  memset (recv_buffer, 0, sizeof (recv_buffer));
  while (!transmission_end_flag) {
    j = 0;
    memset (drop_chunks, 0, sizeof (uint8_t) * g_chunks);
    while (!drop_packet_flag) {
      recv_bytes = recvfrom (udp_sockfd, recv_buffer, MAX_BUF_SIZE, 0,
			     (struct sockaddr *) &cli_addr_udp, &servlen);
      //fprintf(stdout, "Received dropped packets\n");
      if (recv_bytes < 0) {
	continue;
      }
      if (recv_bytes > 0) {
	p = 0;
	while (p * SEQ_NUM_SIZE < recv_bytes) {
	  drop_chunks[j] = GET_UINT32 ((recv_buffer + p * SEQ_NUM_SIZE));
	  j++;
	  p++;
	}
      }
      memset (recv_buffer, 0, sizeof (recv_buffer));
      recv_bytes = -1;
    }
    drop_packet_flag = FALSE;
    iteration++;
    fprintf (stdout, "Drop Packets received: %d\n", j);

#if DEBUG_PRINT
    fprintf (stdout, "Batch of dropped packet received - %d\n", iteration);
#endif //DEBUG

    g_dropped_chunks = j;
    g_tx_chunks -= g_dropped_chunks;
    retransmit_dropped_packets ();

#if DEBUG_PRINT
    fprintf (stdout, "Going to set send_end_flag\n");
#endif //DEBUG
  }

  fprintf (stdout, "Drop packet thread exits: %s", get_time ());
}

void *
create_tcp_server (void *arg)
{
  char buffer[MAX_BUF_SIZE];
  int retval;
  char *ptr = buffer;
  int counter = 0;
  char seq_no[15];
  int i;

  char *space_ptr = NULL;
  int j = 0;
  int p = 0;

  /* Wait for START from client */
  memset (buffer, 0, sizeof (buffer));
  retval = read (tcp_newsockfd, buffer, sizeof (buffer));
  if (retval < 0) {
    error ("Error reading from socket. Waiting for start from client");
  }

  if (strcmp ((buffer), "START") != 0) {
    error ("Corrupted start message");
  }

  start_flag = TRUE;

  /* Wait for start send signal */
  memset (buffer, 0, sizeof (buffer));
  int threadspawn = 1;

  pthread_t drop_tid;
WAIT_DROP:
  /* Wait for end send signal */
  while (send_end_flag == FALSE);
  retval = write (tcp_newsockfd, "END", 4);
  if (retval < 0) {
    error ("Error reading from socket. Waiting for end signal from client");
  }
#if DEBUG_PRINT
  fprintf (stdout, "END flag sent %s\n", get_time ());
#endif //DEBUG
  send_end_flag = FALSE;

  if (threadspawn == 1) {
    threadspawn = 0;
    pthread_create (&drop_tid, NULL, drop_packets, NULL);
  }

  /* Receive dropped packets */
  while (1) {
    memset (buffer, 0, sizeof (buffer));
    retval = read (tcp_newsockfd, buffer, sizeof (buffer));
    if (retval < 0) {
      error ("Error reading from socket. Waiting for dropped packets");
    }
    fprintf (stdout, "++++++++++++++++++++++++++++\n");
#if DEBUG_PRINT
    fprintf (stdout, "Drop buffer is: %s\n", buffer);
#endif //DEBUG
    if (strcmp (buffer, "TRANSMISSION END") == 0) {
      transmission_end_flag = TRUE;
      drop_packet_flag = TRUE;
      pthread_join (drop_tid, NULL);
      fprintf (stdout, "++++++++++++++++++++++++++\n");
      return;
    }

    if (strcmp (buffer, "DROP OVER") == 0) {
      drop_packet_flag = TRUE;
      break;
    }
  }
  send_end_flag = FALSE;
  goto WAIT_DROP;
}


int
main (int argc, char *argv[])
{
  struct sockaddr_in serv_addr_tcp;
  int retval, i, pid, readbytes;
  socklen_t clilen;
  char buffer[BYTES_RW];
  int fd;
  char chunk_str[8];
  pthread_t tid, senddata_tid;
  time_t start_time, end_time;
  double time_taken;
  int opt_val = 1;

  time (&start_time);

  if (argc < 3) {
    fprintf (stderr, "\n Usage %s <port number> <file>", argv[0]);
    exit (0);
  }

  memset (buffer, 0, sizeof (buffer));

  /* Get file size */
  g_file_size = get_file_size (argv[2]);

  fprintf (stdout, "FTP Server Enabled.\n");
  fprintf (stdout, "File size - %u Bytes\n", g_file_size);


  /* Open file for reading */
  strcpy (filename, argv[2]);
  g_fd = open (argv[2], O_RDONLY);
  if (g_fd < 0) {
    error ("Cannot open the file");
  }

  g_chunks = (int) (ceil (((double) get_file_size (argv[2]) / MAX_BUF_SIZE)));
  fprintf (stdout, "Chunks    - %d\n", g_chunks);

  drop_chunks = (int *) malloc (sizeof (int) * g_chunks);

  memset (buffer, 0, sizeof (buffer));

  num_chunks = g_chunks;
  file_size = g_file_size;

  drop_buffer = (char *) malloc (sizeof (char) * TCP_SEND_SIZE);
  if (drop_buffer == NULL) {
    error ("Error in malloc");
  }
  memset (drop_buffer, 0, sizeof (char) * TCP_SEND_SIZE);

  recv_pkts = (uint8_t *) malloc (sizeof (uint8_t) * num_chunks);
  if (recv_pkts == NULL) {
    error ("Error in malloc");
  }
  memset (recv_pkts, 0, sizeof (uint8_t) * num_chunks);

  /* Allocate memory to store file data */
  file_data = (char *) malloc (file_size * sizeof (char));
  memset (file_data, '\0', file_size * sizeof (char));

  /* Create TCP socket for transfer */
  tcp_sockfd = socket (AF_INET, SOCK_STREAM, 0);
  setsockopt (tcp_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt_val,
	      sizeof (opt_val));

  bzero ((char *) &serv_addr_tcp, sizeof (serv_addr_tcp));
  serv_addr_tcp.sin_family = AF_INET;
  serv_addr_tcp.sin_addr.s_addr = INADDR_ANY;
  serv_addr_tcp.sin_port = htons (TCP_PORT);

  if (bind (tcp_sockfd, (struct sockaddr *) &serv_addr_tcp,
	    sizeof (serv_addr_tcp)) < 0) {
    error ("ERROR on binding");
  }

  clilen = sizeof (struct sockaddr_in);
  listen (tcp_sockfd, 5);

  tcp_newsockfd = accept (tcp_sockfd, (struct sockaddr *) &cli_addr_tcp,
			  &clilen);
  if (tcp_newsockfd < 0) {
    error ("ERROR on accept");
  }

  handle_control_packets (tcp_newsockfd);

  /* Create UDP socket for transfer */
  udp_sockfd = socket (AF_INET, SOCK_DGRAM, 0);
  if (udp_sockfd < 0) {
    error ("ERROR opening socket");
  }

  transfer_port = atoi (argv[1]);

  memset (buffer, 0, sizeof (buffer));
  fprintf (stdout, "Initiating Transfer.\n");

  /*
   * Packet Structure
   *       +---------+-------+
   *       | SEQ NUM | DATA  |
   *       +---------+-------+
   */

  /* Create thread for TCP socket */
  pthread_create (&tid, NULL, create_tcp_server, NULL);

  /* Create thread for sending data */
  if (pthread_create (&senddata_tid, NULL, SendChunk, NULL) != 0) {
    fprintf (stderr, "Read thread not created successfully - %s\n",
	     strerror (errno));
  }

  pthread_join (senddata_tid, NULL);
  pthread_join (tid, NULL);

  fprintf (stdout, "\nEnd of Transfer.\n");

  close (g_fd);
  close (tcp_sockfd);
  close (udp_sockfd);
  close (tcp_newsockfd);

}
