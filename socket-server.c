/*
 * socket-server.c
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

int main(void)
{
	unsigned char buf[DATA_SIZE];
	char addrstr[INET_ADDRSTRLEN];
	int sd, newsd, count, activity = 0;
	ssize_t n;
	socklen_t len;
	fd_set readfds;
	struct sockaddr_in sa;

    /* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

    struct session_op sess;
	struct crypt_op cryp;
	struct data_op data;

	int cfd;
	cfd = open("/dev/crypto", O_RDWR);
	if (cfd < 0) {
		perror("/dev/crypto)");
		exit (1);
	}
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

	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}
	/* Loop forever, accept()ing connections */
	for (;;) {
		fprintf(stderr, "Waiting for an incoming connection...\n");
		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
			perror("accept");
			exit(1);
		}
		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		fprintf(stderr, "Incoming connection from %s:%d\n",
			addrstr, ntohs(sa.sin_port));

		/* We break out of the loop when the remote peer goes away */
		for (;;) {

			FD_ZERO(&readfds);
			FD_SET(0, &readfds);
			FD_SET(newsd, &readfds);
			activity = select(newsd + 1, &readfds, NULL, NULL, NULL);
			if(activity < 0){
				perror("select");
				exit(1);
			}
			// read from stdin
			if(FD_ISSET(0, &readfds)){
				for(count = 0; count < sizeof(buf)-1; count++ ){
					n = read(0, buf + count, 1);
					if (n < 0) {
						perror("read");
						exit(1);
					}
					// break if error occures
					if (n <= 0)
						break;
					// break if new line found 
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
                if (insist_write(newsd, data.encrypted, DATA_SIZE) != DATA_SIZE) {
					perror("write to remote peer failed");
					return 1;
				}
			}
			if(FD_ISSET(newsd, &readfds)){
				// if client leaves that helps us not print stuff left in buffer 
				fflush(stdout);
				fflush(stdin);
				n = read(newsd, buf, sizeof(buf));
				if (n <= 0) {
					if (n < 0)
						perror("read from remote peer failed");
					else
						fprintf(stderr, "Peer went away\n");
					break;
				}

	            cryp.src = buf;
	            cryp.dst = data.decrypted;
	            cryp.op  = COP_DECRYPT;
	   			// encrypt the data
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
		/* Make sure we don't leak open files */
		if (close(newsd) < 0)
			perror("close");
	}


	/* This will never happen */
	return 1;
}

