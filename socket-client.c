/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 * Vasileios Anagnostoulis 
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <crypto/cryptodev.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;

	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}


int main(int argc, char *argv[])
{
	int sd, port, count, activity = 0;
	ssize_t n;
	unsigned char buf[DATA_SIZE];
	char *hostname;
	fd_set readfds;
	struct hostent *hp;
	struct sockaddr_in sa;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}
	
	/* Connect to remote TCP port */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

	int cfd;
	cfd = open("/dev/crypto", O_RDWR);
	if (cfd < 0) {
		perror("/dev/crypto)");
		exit (1);
	}

    struct session_op sess;
	struct crypt_op cryp;
	struct data_op data;
	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));

	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = KEY;

	if (ioctl(cfd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}
	cryp.ses = sess.ses;
	cryp.len = DATA_SIZE;
	cryp.iv = IV;

	for(;;){
		FD_ZERO(&readfds);
		FD_SET(0, &readfds);
		FD_SET(sd, &readfds);
		activity = select(sd + 1, &readfds, NULL, NULL, NULL);
		if(activity < 0){
			perror("select");
			exit(1);
		}
		if(FD_ISSET(0, &readfds)){
			for(count = 0; count < sizeof(buf)-1; count++ ){
				n = read(0, buf + count, 1);
				if (n < 0) {
					perror("read");
					exit(1);
				}
				if (n <= 0)
					break;
				if (buf[count] == '\n')
					break;
			}
			buf[count+1] = '\0';

			cryp.src = buf;
        	cryp.dst = data.encrypted;
        	cryp.op  = COP_ENCRYPT;
   			// encrypt the data
   			if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                    perror("ioctl(CIOCCRYPT)");
                    return 1;
            }
			if (insist_write(sd, data.encrypted,DATA_SIZE) != DATA_SIZE) {
				perror("write to remote peer failed");
				return 1;
			}
		}
		// READ FROM SOCKET
		if(FD_ISSET(sd, &readfds)){
			// if peer leaves that helps us not print stuff left in buffer 
			fflush(stdout);
			fflush(stdin);
			/* Read answer and write it to standard output */
			n = read(sd, buf, sizeof(buf));
			if (n <= 0) {
			if (n < 0)
					perror("read from remote peer failed");
				else
					fprintf(stderr, "Server is down\n");
				break;
			}
		
			cryp.src = buf;
            cryp.dst = data.decrypted;
            cryp.op  = COP_DECRYPT;

            /* call ioctl for decryption */
            if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                perror("ioctl(CIOCCRYPT)");
                return 1;
            }

			fprintf(stdout, "\nRemote said:\n");
			if (insist_write(1, data.decrypted, strlen((const char*)data.decrypted)) != strlen((const char*)data.decrypted)) {
				perror("write");
				exit(1);
			}
			fprintf(stdout, "\n");
		}
	}

	if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
		return 1;
	}
    if (close(cfd) < 0) {
        perror("close");
        exit(1);
    }
    if (shutdown(sd, SHUT_WR) < 0) {
        perror("shutdown");
        exit(1);
    }
	fprintf(stderr, "\nDone.\n");
	return 0;
}
