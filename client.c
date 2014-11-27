/* 
 * A simple FTP client in the internet domain using UDP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <signal.h>
#include <netdb.h>
#include <assert.h>
#include <openssl/md5.h>
#include "common.h"

static uint32_t chunks_rx = 0;
static uint32_t file_size = 0;
static uint32_t num_chunks = 0;
static int tcp_sockfd;
static int udp_sockfd;
static int prev_read = MAX_BUF_SIZE;
static int recv_complete_flag = FALSE;
static int all_received = TRUE;
static int g_fd;

char *file_data;
struct sockaddr_in serv_addr_tcp;
struct sockaddr_in serv_addr_udp;
struct sockaddr_in cli_addr_udp;
static int iteration = 0;
socklen_t servlen;

uint8_t *recv_pkts;
char *drop_buffer;

char recv_digest[MD5_DIGEST_LENGTH];

static int g_file_size = 0;
static int g_chunks = 0;

static uint32_t g_tx_chunks = 0;
static uint32_t g_dropped_chunks = 0;
int *drop_chunks = NULL;

static int start_flag = FALSE;
static int end_flag = FALSE;
static int send_end_flag = FALSE;
static int transmission_end_flag = FALSE;
static int drop_packet_flag = FALSE;
static int last_chunk_size;

void
retransmit_dropped_packets (void)
{
  int counter = 0, retval;
  char buffer[BYTES_RW];
  int tocpy = 0;
  int sent_size = 0;

  memset (buffer, 0, sizeof (buffer));
  while (counter < g_dropped_chunks) {
    tocpy =
      (drop_chunks[counter] == g_chunks) ? last_chunk_size : MAX_BUF_SIZE;
    assert (drop_chunks[counter] <= g_chunks);
    memcpy ((buffer + SEQ_NUM_SIZE),
	    (file_data + drop_chunks[counter] * MAX_BUF_SIZE), tocpy);
    PUT_UINT32 (&buffer[0], drop_chunks[counter]);
    retval = fcntl (udp_sockfd, F_SETFL,
		    fcntl (udp_sockfd, F_GETFL) & ~O_NONBLOCK);
    if (retval < 0) {
      error ("FNCTL error");
    }
    retval = sendto (udp_sockfd, buffer, (tocpy + SEQ_NUM_SIZE), 0,
		     (struct sockaddr *) &serv_addr_udp,
		     sizeof (cli_addr_udp));
    if (retval < 0) {
      error ("error could not sent retransmit dropped packets");
    }
    retval = fcntl (udp_sockfd, F_SETFL,
		    fcntl (udp_sockfd, F_GETFL) | O_NONBLOCK);
    if (retval < 0) {
      error ("FNCTL error");
    }
    g_tx_chunks++;
    memset (buffer, 0, sizeof (buffer));
    counter++;
  }
  send_end_flag = TRUE;

#if DEBUG_PRINT
  fprintf (stdout, "Retransmissed Packets %d\n", counter);
#endif
}

/* Handle control packets using TCP socket */
void *
handle_control (void *arg)
{
  int retval, i, counter = 0;
  char buffer[MAX_BUF_SIZE];
  int prev_iteration = iteration;

  memset (buffer, 0, sizeof (buffer));

  retval = write (tcp_sockfd, "START", 5);
  if (retval < 0) {
    error ("ERROR START could not be sent");
  }

SEND_DROP:
  /* Waiting for file transfer end */

#if DEBUG_PRINT
  fprintf (stdout, "Waiting for END\n");
#endif

  retval = read (tcp_sockfd, buffer, sizeof (buffer));
  if (retval < 0) {
    error ("ERROR reading from socket");
  }

#if DEBUG_PRINT
  fprintf (stdout, "END received: %s, %s\n", buffer, get_time ());
#endif

  if (strcmp (buffer, "END") == 0) {
    recv_complete_flag = TRUE;
#if DEBUG_PRINT
    fprintf (stdout, "END received: %s, %s\n", buffer, get_time ());
#endif
  }
  fprintf (stdout, "recvfrom status - %d\n",
	   fcntl (udp_sockfd, F_GETFL) & O_NONBLOCK);

  while (prev_iteration == iteration) {
    retval = fcntl (udp_sockfd, F_SETFL,
		    fcntl (udp_sockfd, F_GETFL) | O_NONBLOCK);
    if (retval != 0) {
      fprintf (stdout, "FNCTL error");
    }
  }

  fprintf (stdout, "Next iteration found - %d\n", iteration);

#if DEBUG_PRINT
  fprintf (stdout, "Dropped packets - %d\n", (num_chunks - chunks_rx));
#endif
  fprintf (stdout, "Iteration - %d\n", iteration);
  prev_iteration = iteration;

  int cnt = 0;
  for (i = 0; i < num_chunks; i++) {
    if (recv_pkts[i] == TRUE) {
      cnt++;
    }
  }

  fprintf (stdout, "Received Packets Counter - %d\n", cnt);
  int s = 0, p = 0;
  int verify = 0;
  memset (drop_buffer, '\0', sizeof (char) * TCP_SEND_SIZE);

  for (i = 0; i < num_chunks; i++) {
    if (recv_pkts[i] == FALSE) {
      all_received = FALSE;
      if (s == (TCP_SEND_SIZE)) {
	s = 0;
	p = 0;

	retval = fcntl (udp_sockfd, F_SETFL,
			fcntl (udp_sockfd, F_GETFL) & ~O_NONBLOCK);
	if (retval != 0) {
	  fprintf (stdout, "FNCTL error");
	}
	retval = sendto (udp_sockfd, drop_buffer, TCP_SEND_SIZE, 0,
			 (struct sockaddr *) &serv_addr_udp,
			 sizeof (cli_addr_udp));
	if (retval < 0) {
	  error ("Error writing to socket. DROP BUFFER");
	}

	retval = fcntl (udp_sockfd, F_SETFL,
			fcntl (udp_sockfd, F_GETFL) | O_NONBLOCK);
	if (retval != 0) {
	  fprintf (stdout, "FNCTL error");
	}

	memset (buffer, '\0', sizeof (buffer));
	memset (buffer, 0, sizeof (buffer));
	memset (drop_buffer, '\0', sizeof (char) * TCP_SEND_SIZE);
      }
      verify++;
      PUT_UINT32 (&drop_buffer[p * 4], i);
      p++;
      s = p * 4;
    }
  }

  if (s != 0) {
    retval = fcntl (udp_sockfd, F_SETFL,
		    fcntl (udp_sockfd, F_GETFL) & ~O_NONBLOCK);
    if (retval != 0) {
      fprintf (stdout, "FNCTL error");
    }

    retval = sendto (udp_sockfd, drop_buffer, s, 0,
		     (struct sockaddr *) &serv_addr_udp,
		     sizeof (serv_addr_udp));
    if (retval < 0) {
      error ("Error writing to socket. DROP BUFFER");
    }

    retval = fcntl (udp_sockfd, F_SETFL,
		    fcntl (udp_sockfd, F_GETFL) | O_NONBLOCK);
    if (retval != 0) {
      fprintf (stdout, "FNCTL error");
    }

    memset (buffer, '\0', sizeof (buffer));
  }


  if (verify == 0 && all_received == TRUE) {
    retval = write (tcp_sockfd, "TRANSMISSION END", 18);
    if (retval < 0) {
      error ("Error writing to socket");
    }
    recv_complete_flag = TRUE;
    fprintf (stdout, "End of control thread\n");
    chunks_rx = num_chunks;
    fprintf (stdout, "Transmission end sent\n");
    return;
  }
  else {
    retval = write (tcp_sockfd, "DROP OVER", 10);
    if (retval < 0) {
      error ("Error writing to socket. DROP OVER");
    }
    fprintf (stdout, "Drop over sent\n");
  }

  all_received = TRUE;
  memset (drop_buffer, 0, sizeof (char) * TCP_SEND_SIZE);
  goto SEND_DROP;
}

void *
handle_data (void *arg)
{
  char recv_buffer[BYTES_RW];
  ssize_t recv_bytes;
  int seqno;

  fprintf (stdout, "UDP socket, reading file packets.. %d\n", chunks_rx);
  chunks_rx = 0;
  memset (recv_buffer, 0, sizeof (recv_buffer));

  while (chunks_rx != num_chunks) {
    prev_read = MAX_BUF_SIZE;
    while (!recv_complete_flag) {
      recv_bytes = recvfrom (udp_sockfd, recv_buffer, BYTES_RW, 0,
			     (struct sockaddr *) &serv_addr_udp, &servlen);
      if (recv_bytes < 0) {
	continue;
      }
      if (recv_bytes > 0) {
	seqno = GET_UINT32 (recv_buffer);
	assert (seqno <= num_chunks);
	if (recv_pkts[seqno] == FALSE) {
	  chunks_rx++;
	  recv_pkts[seqno] = TRUE;
	  memcpy ((file_data + seqno * prev_read),
		  (recv_buffer + SEQ_NUM_SIZE), (recv_bytes - SEQ_NUM_SIZE));
	  prev_read = recv_bytes - SEQ_NUM_SIZE;
	  if (seqno == g_chunks) {
	    last_chunk_size = prev_read;
	  }
	}
      }
      memset (recv_buffer, 0, sizeof (recv_buffer));
      recv_bytes = -1;
    }

#if DEBUG_PRINT
    fprintf (stdout, "Packets received: %d\n", chunks_rx);
#endif
    recv_complete_flag = FALSE;
    recv_bytes = -1;
    iteration++;
  }
}

int
main (int argc, char **argv)
{
  struct hostent *server;
  int retval, i;
  unsigned char digest[MD5_DIGEST_LENGTH];
  char chunk_char[8];
  pthread_t tid, uid;
  char buffer[MAX_BUF_SIZE];
  void *tid_result, *uid_result;

  memset (buffer, 0, sizeof (buffer));
  memset (digest, 0, sizeof (digest));

  if (argc < 4) {
    fprintf (stderr, "usage %s <hostname> <port> <filename>\n", argv[0]);
    exit (0);
  }

  /* Check if server exists */
  server = gethostbyname (argv[1]);
  if (server == NULL) {
    fprintf (stderr, "ERROR, no such host\n");
    exit (0);
  }

  /* Open file to write data */
  g_fd = open (argv[3], O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  if (g_fd < 0) {
    error ("ERROR opening the file");
  }

  tcp_sockfd = socket (AF_INET, SOCK_STREAM, 0);
  if (tcp_sockfd < 0) {
    error ("Error creating TCP socket on client");
  }

  bzero ((char *) &serv_addr_tcp, sizeof (serv_addr_tcp));
  bcopy ((char *) server->h_addr, (char *) &serv_addr_tcp.sin_addr.s_addr,
	 server->h_length);
  serv_addr_tcp.sin_family = AF_INET;
  serv_addr_tcp.sin_port = htons (TCP_PORT);

  if (connect (tcp_sockfd, (struct sockaddr *) &serv_addr_tcp,
	       sizeof (serv_addr_tcp)) < 0) {
    error ("ERROR in TCP connect on client");
  }

  fprintf (stdout, "Connected to TCP server\n");

  /* Get file size and number of chunks */
  retval = read (tcp_sockfd, buffer, sizeof (buffer));
  if (retval < 0) {
    error ("ERROR reading from socket");
  }

  retval = sscanf (buffer, "%u %u", &file_size, &num_chunks);

  memset (buffer, 0, sizeof (buffer));

  fprintf (stdout, "File Size - %u bytes\n", file_size);
  fprintf (stdout, "Num chunks - %u\n", num_chunks);
  memset (buffer, 0, sizeof (buffer));

  g_chunks = num_chunks;
  drop_chunks = (int *) malloc (sizeof (int) * g_chunks);
  memset (drop_chunks, 0, sizeof (int) * g_chunks);


  drop_buffer = (char *) malloc (sizeof (char) * TCP_SEND_SIZE);
  if (drop_buffer == NULL) {
    error ("Error in malloc");
  }
  memset (drop_buffer, 0, (sizeof (char) * TCP_SEND_SIZE));

  recv_pkts = (uint8_t *) malloc (sizeof (uint8_t) * num_chunks);
  if (recv_pkts == NULL) {
    error ("Error in malloc");
  }

  memset (recv_pkts, 0, sizeof (uint8_t) * num_chunks);

  /* Socket call for UDP socket */
  udp_sockfd = socket (AF_INET, SOCK_DGRAM, 0);
  if (udp_sockfd < 0) {
    error ("ERROR opening UDP socket on client");
  }

  bzero ((char *) &serv_addr_udp, sizeof (serv_addr_udp));
  serv_addr_udp.sin_addr.s_addr = INADDR_ANY;
  serv_addr_udp.sin_family = AF_INET;
  serv_addr_udp.sin_port = htons (atoi (argv[2]));

  retval = bind (udp_sockfd, (struct sockaddr *) &serv_addr_udp,
		 sizeof (serv_addr_udp));
  if (retval < 0) {
    error ("ERROR on binding on UDP at client");
  }

  retval = fcntl (udp_sockfd, F_SETFL,
		  fcntl (udp_sockfd, F_GETFL) | O_NONBLOCK);
  if (retval != 0) {
    fprintf (stdout, "FNCTL error");
  }

  /* Allocate memory to store file data */
  file_data = (char *) malloc (file_size * sizeof (char));
  memset (file_data, 0, file_size * sizeof (char));

  /* Create thread for TCP */
  pthread_create (&tid, NULL, &handle_control, NULL);
  pthread_create (&uid, NULL, &handle_data, NULL);

  pthread_join (tid, &tid_result);
  pthread_join (uid, &uid_result);

  write (g_fd, file_data,
	 (((chunks_rx - 1) * MAX_BUF_SIZE) + prev_read) * sizeof (char));

  fprintf (stdout, "Transfer end time: %s", get_time ());
  fprintf (stdout, "Transfer completed.\n");


#if DEBUG
  /* Generate checksum */
  gen_checksum (argv[3], digest);
  fprintf (stdout, "Generated checksum - ");
  for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
    printf ("%02x", digest[i]);
  }
  printf ("\n");
#endif

  close (g_fd);
  free (file_data);
  close (tcp_sockfd);
  close (udp_sockfd);
  free (recv_pkts);
  free (drop_buffer);

  return 0;
}
