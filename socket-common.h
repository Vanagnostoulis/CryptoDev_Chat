/*
 * socket-common.h
 *
 * Simple TCP/IP communication using sockets
 *
 * Vasileios Anagnostoulis
 */

#ifndef _SOCKET_COMMON_H
#define _SOCKET_COMMON_H

/* Compile-time options */
#define TCP_PORT    35001
#define TCP_BACKLOG 5

#define DATA_SIZE 		128  /* AES128 */
#define BLOCK_SIZE      16
#define KEY_SIZE		16  /* AES128 */

unsigned char KEY[]="SA342JAID857FA3JF";
unsigned char  IV[]="S12D2JA3TL57FA3GS";

struct data_op{
		unsigned char encrypted[DATA_SIZE],
				      decrypted[DATA_SIZE];
};

#endif /* _SOCKET_COMMON_H */

