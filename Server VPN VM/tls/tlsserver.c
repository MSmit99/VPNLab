#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define BUFF_SIZE 2000

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));
   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);
   return tunfd;
}

int setupTCPServer() {
    struct sockaddr_in sa_server;
    int listen_sock;
    listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset(&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons(4433);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

int main() {
    SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;
    int err;

    // TLS initialization
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // Load server certificate and key
    SSL_CTX_use_certificate_file(ctx, "./cert_server/server-cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/server-key.pem", SSL_FILETYPE_PEM);

    // Create TUN device
    int tunfd = createTunDevice();

    // Set up TCP server and wait for connection
    int listen_sock = setupTCPServer();
    printf("Waiting for client connection...\n");

    struct sockaddr_in sa_client;
    socklen_t client_len = sizeof(sa_client);
    int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);

    // TLS handshake
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    err = SSL_accept(ssl);
    CHK_SSL(err);
    printf("TLS connection established!\n");

    // Main tunnel loop
    while (1) {
        fd_set readFDSet;
        char buff[BUFF_SIZE];
        int len;

        FD_ZERO(&readFDSet);
        FD_SET(sock, &readFDSet);
        FD_SET(tunfd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        // Packet from TUN -> send through TLS tunnel
        if (FD_ISSET(tunfd, &readFDSet)) {
            printf("Got a packet from TUN\n");
            bzero(buff, BUFF_SIZE);
            len = read(tunfd, buff, BUFF_SIZE);
            SSL_write(ssl, buff, len);
        }

        // Packet from TLS tunnel -> send to TUN
        if (FD_ISSET(sock, &readFDSet)) {
            printf("Got a packet from the tunnel\n");
            bzero(buff, BUFF_SIZE);
            len = SSL_read(ssl, buff, BUFF_SIZE);
            if (len > 0) write(tunfd, buff, len);
        }
    }
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}