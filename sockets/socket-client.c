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

    /**
     * Crypto
     */
    struct session_op sess;
    struct crypt_op cryp;

    int cfd = open("/dev/cryptodev0", O_RDONLY);

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
    sess.key    = KEY;

	if (ioctl(cfd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}

    cryp.ses = sess.ses;
    cryp.len = DATA_SIZE;
    cryp.iv  = IV;

    struct {
        unsigned char 
            encrypted[DATA_SIZE],
            decrypted[DATA_SIZE]
    } data;

    int activity, i = 0;
    /**
     * Eternal loop
     */
    for (;;) {
        /**
         * readfds is used to select
         * which fd is ready to be read
         */
        fd_set readfds;

        FD_ZERO(&readfds);

        FD_SET(0, &readfds);
        FD_SET(sd, &readfds);

        /* check if some fd is ready */
        activity = select(sd + 1, &readfds, NULL, NULL, NULL);

        if (activity < 0) {
            perror("select");
            exit(-1);
        }

        if (FD_ISSET(0, &readfds)) {
            /**
             * Read from stdin.
             * Reads until newline ('\n')
             */
            for (;;) {
                n = read(0, buf, sizeof(buf));

                if (n < 0) {
                    perror("read");
                    exit(1);
                }

                int k;
                /* Fill remaining of buffer */
                for (k = n; k < DATA_SIZE; k++)
                    buf[k] = 0;

                /* In error break */
                if (n <= 0)
                    break;

                cryp.src = buf;
                cryp.dst = data.encrypted;
                cryp.op  = COP_ENCRYPT;

                /* call ioctl for encryption */
                if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                    perror("ioctl(CIOCCRYPT)");
                    return 1;
                }

                /* write results to file descriptor of socket */
                if (insist_write(sd, data.encrypted, DATA_SIZE) != DATA_SIZE) {
                    perror("write");
                    exit(1);
                }

                /* if last char read is newline then stop reading */
                if (buf[n - 1] == '\n')
                    break;
            }
            
        }

        if (FD_ISSET(sd, &readfds)) {
            /**
             * Read from socket
             * Reads until newline is found
             */
            /* i is used to print 'Other' only once */
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

                cryp.src = buf;
                cryp.dst = data.decrypted;
                cryp.op  = COP_DECRYPT;

                /* call ioctl for decryption */
                if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                    perror("ioctl(CIOCCRYPT)");
                    return 1;
                }

                /* write results to stdout*/
                if (insist_write(1, data.decrypted, n) != n) {
                    perror("write");
                    exit(1);
                }

                /* check if newline found */
                int j, found = 0;
                for (j = 0; j < DATA_SIZE; j++) {
                    if (data.decrypted[j] == '\n') {
                        found = 1;
                        break;
                    }
                }
                if (found)
                    break;
            }
        }

    }

	if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
		return 1;
	}

	/*
	 * Let the remote know we're not going to write anything else.
	 * Try removing the shutdown() call and see what happens.
	 */
    if (shutdown(sd, SHUT_WR) < 0) {
        perror("shutdown");
        exit(1);
    }

    if (close(cfd) < 0) {
        perror("close");
        exit(1);
    }

	fprintf(stderr, "\nDone.\n");
	return 0;
}
