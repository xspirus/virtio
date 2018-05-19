/*
 * socket-common.h
 *
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#ifndef _SOCKET_COMMON_H
#define _SOCKET_COMMON_H

/* Compile-time options */
#define TCP_PORT    35001
#define TCP_BACKLOG 5

#define HELLO_THERE "Hello there!"

#define DATA_SIZE   100
#define KEY_SIZE    16
#define BLOCK_SIZE  16

unsigned char KEY[] = "B2D996CA64772FFD";
unsigned char IV[]  = "B2B95343EA01B4C6";

#endif /* _SOCKET_COMMON_H */

