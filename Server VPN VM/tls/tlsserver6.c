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
#include <shadow.h>
#include <crypt.h>
#include <sys/wait.h>

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define BUFF_SIZE 2000
#define MAX_CLIENTS 10

struct ClientInfo {
    int pipe_fd;
    in_addr_t tun_ip;
    pid_t pid;
};

struct ClientInfo clients[MAX_CLIENTS];
int num_clients = 0;

int createTunDevice() {
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);
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

int authenticate(SSL* ssl) {
    char username[100];
    char password[100];

    memset(username, 0, sizeof(username));
    int len = SSL_read(ssl, username, sizeof(username) - 1);
    if (len <= 0) return 0;
    username[len] = '\0';
    printf("Authentication attempt for user: %s\n", username);

    memset(password, 0, sizeof(password));
    len = SSL_read(ssl, password, sizeof(password) - 1);
    if (len <= 0) return 0;
    password[len] = '\0';

    struct spwd *pw = getspnam(username);
    if (pw == NULL) {
        printf("User not found: %s\n", username);
        return 0;
    }

    char *epasswd = crypt(password, pw->sp_pwdp);
    if (strcmp(epasswd, pw->sp_pwdp) != 0) {
        printf("Authentication failed for user: %s\n", username);
        return 0;
    }

    printf("Authentication successful for user: %s\n", username);
    return 1;
}

in_addr_t getDestIP(char *buff) {
    struct in_addr dest;
    memcpy(&dest, buff + 16, sizeof(dest));
    return dest.s_addr;
}

in_addr_t getSrcIP(char *buff) {
    struct in_addr src;
    memcpy(&src, buff + 12, sizeof(src));
    return src.s_addr;
}

void childProcess(SSL *ssl, int tunfd, int pipe_read_fd) {
    char buff[BUFF_SIZE];
    int len;
    int sockfd = SSL_get_fd(ssl);

    while (1) {
        fd_set readFDSet;
        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(pipe_read_fd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        // Packet from TLS tunnel -> write to TUN
        if (FD_ISSET(sockfd, &readFDSet)) {
            printf("Child: Got packet from tunnel\n");
            bzero(buff, BUFF_SIZE);
            len = SSL_read(ssl, buff, BUFF_SIZE);
            if (len > 0) write(tunfd, buff, len);
        }

        // Packet from pipe (parent) -> send through TLS tunnel
        if (FD_ISSET(pipe_read_fd, &readFDSet)) {
            printf("Child: Got packet from pipe\n");
            bzero(buff, BUFF_SIZE);
            len = read(pipe_read_fd, buff, BUFF_SIZE);
            if (len > 0) SSL_write(ssl, buff, len);
        }
    }
}

int main() {
    SSL_METHOD *meth;
    SSL_CTX *ctx;
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

    // Set up TCP server
    int listen_sock = setupTCPServer();
    printf("Waiting for client connections...\n");

    fd_set readFDSet;

    while (1) {
        FD_ZERO(&readFDSet);
        FD_SET(listen_sock, &readFDSet);
        FD_SET(tunfd, &readFDSet);

        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        // New client connection
        if (FD_ISSET(listen_sock, &readFDSet)) {
            struct sockaddr_in sa_client;
            socklen_t client_len = sizeof(sa_client);
            int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);

            // Create pipe for parent->child communication
            int pipefd[2];
            pipe(pipefd);

            pid_t pid = fork();
            if (pid == 0) {
                // Child process
                close(pipefd[1]); // child only reads from pipe
                close(listen_sock); // child does not need listen socket

                // TLS handshake
                SSL *ssl = SSL_new(ctx);
                SSL_set_fd(ssl, sock);
                err = SSL_accept(ssl);
                CHK_SSL(err);
                printf("Child: TLS connection established!\n");

                // Authenticate
                if (!authenticate(ssl)) {
                    printf("Child: Authentication failed. Closing.\n");
                    SSL_write(ssl, "AUTH_FAIL", 9);
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    close(sock);
                    exit(1);
                }

                // Send auth success
                SSL_write(ssl, "AUTH_OK", 7);

                // Run child tunnel loop
                childProcess(ssl, tunfd, pipefd[0]);
                exit(0);

            } else {
                // Parent process
                close(pipefd[0]); // parent only writes to pipe
                close(sock);      // parent does not handle this socket

                // Store client info
                clients[num_clients].pipe_fd = pipefd[1];
                clients[num_clients].tun_ip  = 0;
                clients[num_clients].pid     = pid;
                num_clients++;
                printf("Parent: New client connected. Total clients: %d\n", num_clients);
            }
        }

        // Packet from TUN (private network) -> route to correct client
        if (FD_ISSET(tunfd, &readFDSet)) {
            char buff[BUFF_SIZE];
            bzero(buff, BUFF_SIZE);
            int len = read(tunfd, buff, BUFF_SIZE);
            if (len > 0) {
                in_addr_t src_ip  = getSrcIP(buff);
                in_addr_t dest_ip = getDestIP(buff);

                // Learn client TUN IP from first packet
                int i;
                for (i = 0; i < num_clients; i++) {
                    if (clients[i].tun_ip == 0) {
                        clients[i].tun_ip = dest_ip;
                        printf("Parent: Learned client %d TUN IP: %s\n", i,
                               inet_ntoa(*(struct in_addr*)&dest_ip));
                        break;
                    }
                }

                // Route packet to correct client based on dest IP
                for (i = 0; i < num_clients; i++) {
                    if (clients[i].tun_ip == dest_ip) {
                        printf("Parent: Routing packet to client %d\n", i);
                        write(clients[i].pipe_fd, buff, len);
                        break;
                    }
                }
            }
        }
    }

    SSL_CTX_free(ctx);
    return 0;
}