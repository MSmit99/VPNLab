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
#include <netdb.h>

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define BUFF_SIZE 2000
#define CA_DIR "ca_client"

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));
   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);
   return tunfd;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    char buf[300];
    X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);
    if (preverify_ok == 1) {
        printf("Verification passed.\n");
    } else {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
    }
    return preverify_ok;
}

SSL* setupTLSClient(const char* hostname) {
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    if (SSL_CTX_load_verify_locations(ctx, NULL, CA_DIR) < 1) {
        printf("Error setting the verify locations.\n");
        exit(0);
    }
    ssl = SSL_new(ctx);
    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);
    return ssl;
}

int setupTCPClient(const char* hostname, int port) {
    struct sockaddr_in server_addr;
    struct hostent *hp = gethostbyname(hostname);
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&server_addr, '\0', sizeof(server_addr));
    memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    server_addr.sin_port   = htons(port);
    server_addr.sin_family = AF_INET;
    connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    return sockfd;
}

int main(int argc, char *argv[]) {
    char *hostname = "vpnlabserver.com";
    int port = 4433;
    if (argc > 1) hostname = argv[1];
    if (argc > 2) port = atoi(argv[2]);

    // TLS setup
    SSL *ssl = setupTLSClient(hostname);

    // TCP connection
    int sockfd = setupTCPClient(hostname, port);

    // TLS handshake
    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl); CHK_SSL(err);
    printf("TLS connection established!\n");
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    // Create TUN device
    int tunfd = createTunDevice();

    // Main tunnel loop
    while (1) {
        fd_set readFDSet;
        char buff[BUFF_SIZE];
        int len;

        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
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
        if (FD_ISSET(sockfd, &readFDSet)) {
            printf("Got a packet from the tunnel\n");
            bzero(buff, BUFF_SIZE);
            len = SSL_read(ssl, buff, BUFF_SIZE);
            if (len > 0) write(tunfd, buff, len);
        }
    }
    close(sockfd);
    SSL_free(ssl);
    return 0;
}