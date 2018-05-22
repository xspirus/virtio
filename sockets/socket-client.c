/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <crypto/cryptodev.h>

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
	int sd, port;
	ssize_t n;
	unsigned char buf[DATA_SIZE];
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;
    struct session_op sess;
    struct crypt_op cryp;

    int cfd = open("/dev/crypto", O_RDONLY);

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
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

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

    int activity, i = 0;
    /**
     * Eternal loop
     */
    for (;;) {
        fd_set readfds;

        FD_ZERO(&readfds);

        FD_SET(0, &readfds);
        FD_SET(sd, &readfds);

        activity = select(sd + 1, &readfds, NULL, NULL, NULL);

        if (activity < 0) {
            perror("select");
            exit(-1);
        }

        if (FD_ISSET(0, &readfds)) {
            /**
             * Read from stdin
             */
            for (;;) {
                n = read(0, buf, sizeof(buf));

                if (n < 0) {
                    perror("read");
                    exit(1);
                }

                if (n <= 0)
                    break;

                struct {
                    unsigned char in[DATA_SIZE],
                                encrypted[DATA_SIZE],
                                decrypted[DATA_SIZE],
                                iv[BLOCK_SIZE],
                                key[KEY_SIZE];
                } data;

                cryp.src = buf;
                cryp.dst = data.encrypted;
                cryp.op = COP_ENCRYPT;

                if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                    perror("ioctl(CIOCCRYPT)");
                    return 1;
                }

                int j;
                fprintf(stderr, "\nTo encrypt :\n");
                for (j = 0; j < n; j++)
                    fprintf(stderr, "%x", buf[j]);
                fprintf(stderr, "\n");
                fprintf(stderr, "\nEncrypted :\n");
                for (j = 0; j < n; j++)
                    fprintf(stderr, "%x", data.encrypted[j]);
                fprintf(stderr, "\n");

                if (insist_write(sd, data.encrypted, n) != n) {
                    perror("write");
                    exit(1);
                }

                if (buf[n - 1] == '\n')
                    break;
            }
            
        }

        if (FD_ISSET(sd, &readfds)) {
            /**
             * Read from socket
             */
            i = 0;
            for (;;) {
                n = read(sd, buf, sizeof(buf));

                if (n < 0) {
                    perror("read");
                    exit(1);
                }

                if (i == 0) {
                    fprintf(stdout, "\nOther : ");
                    fflush(stdout);
                    i++;   
                }

                struct {
                    unsigned char in[DATA_SIZE],
                                encrypted[DATA_SIZE],
                                decrypted[DATA_SIZE],
                                iv[BLOCK_SIZE],
                                key[KEY_SIZE];
                } data;

                cryp.src = buf;
                cryp.dst = data.decrypted;
                cryp.op = COP_DECRYPT;

                if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                    perror("ioctl(CIOCCRYPT)");
                    return 1;
                }

                cryp.src = data.decrypted;
                cryp.dst = data.encrypted;
                cryp.op = COP_ENCRYPT;

                if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                    perror("ioctl(CIOCCRYPT)");
                    return 1;
                }

                int j;
                fprintf(stderr, "\nMy key is :\n");
                for (j = 0; j < KEY_SIZE; j++)
                    fprintf(stderr, "%x", sess.key[j]);
                fprintf(stderr, "\n");
                fprintf(stderr, "\nMy IV is :\n");
                for (j = 0; j < BLOCK_SIZE; j++)
                    fprintf(stderr, "%x", cryp.iv[j]);
                fprintf(stderr, "\n");
                 
                fprintf(stderr, "\nTo decrypt :\n");
                for (j = 0; j < n; j++)
                    fprintf(stderr, "%x", buf[j]);
                fprintf(stderr, "\n");
                fprintf(stderr, "\nDecrypted :\n");
                for (j = 0; j < n; j++)
                    fprintf(stderr, "%x", data.decrypted[j]);    
                fprintf(stderr, "\n");
                fprintf(stderr, "\nEncrypted esoterically :\n");
                for (j = 0; j < n; j++)
                    fprintf(stderr, "%x", data.encrypted[j]);    
                fprintf(stderr, "\n");

                if (insist_write(1, data.decrypted, n) != n) {
                    perror("write");
                    exit(1);
                }

                if (data.decrypted[n - 1] == '\n')
                    break;
            }
            fprintf(stdout, "\n");
            fflush(stdout);
        }

    }

	/* Be careful with buffer overruns, ensure NUL-termination */
	/* strncpy(buf, HELLO_THERE, sizeof(buf)); */
	/* buf[sizeof(buf) - 1] = '\0'; */

	/* [> Say something... <] */
	/* if (insist_write(sd, buf, strlen(buf)) != strlen(buf)) { */
		/* perror("write"); */
		/* exit(1); */
	/* } */
	/* fprintf(stdout, "I said:\n%s\nRemote says:\n", buf); */
	/* fflush(stdout); */

	/* [> Read answer and write it to standard output <] */
	/* for (;;) { */
		/* n = read(sd, buf, sizeof(buf)); */

		/* if (n < 0) { */
			/* perror("read"); */
			/* exit(1); */
		/* } */

		/* if (n <= 0) */
			/* break; */

		/* if (insist_write(0, buf, n) != n) { */
			/* perror("write"); */
			/* exit(1); */
		/* } */
	/* } */

	/*
	 * Let the remote know we're not going to write anything else.
	 * Try removing the shutdown() call and see what happens.
	 */
    if (shutdown(sd, SHUT_WR) < 0) {
        perror("shutdown");
        exit(1);
    }

	fprintf(stderr, "\nDone.\n");
	return 0;
}
