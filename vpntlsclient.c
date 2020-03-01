#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#define PORT_NUMBER 55555
#define SERVER_IP "10.0.2.8"
#define BUFF_SIZE 2000
struct sockaddr_in peerAddr;
#define CREDENTIAL_LEN 256

#define CHK_SSL(err) if ((err) < 1) { \
    perror("Error"); \
    int macro_sslerr = SSL_get_error(ssl, err); \
    fprintf(stderr, "SSL ERROR %d\n", macro_sslerr); \
    ERR_print_errors_fp(stderr); \
    exit(2); \
}
#define CA_DIR "ca_client" 

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
        printf("Verification passed.\n");
        return 1;
    } else {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        printf("Verification failed: %s.\n",
                X509_verify_cert_error_string(err));
        return 0;
    }
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization 
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL* ssl;

    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
        printf("Error setting the verify locations. \n");
        exit(0);
    }
    ssl = SSL_new (ctx);

    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

    return ssl;
}


int setupTCPClient(const char* hostname, int port)
{
    struct sockaddr_in server_addr;

    // Get the IP address from hostname
    // Should replace with getaddrinfo, but out of scope.
    struct hostent* hp = gethostbyname(hostname);
    if (!hp) {
        fprintf(stderr, "hostname lookup fail\n");
        exit(1);    
    }

    // Create a TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // Fill in the destination information (IP, port #, and family)
    memset (&server_addr, '\0', sizeof(server_addr));
    memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    // server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
    server_addr.sin_port   = htons (port);
    server_addr.sin_family = AF_INET;

    // Connect to the destination
    int res = connect(sockfd, (struct sockaddr*) &server_addr,
            sizeof(server_addr));

    if (res == -1) {
        perror("Connect failed.");
        exit(1);
    }

    char addr_as_string[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(server_addr.sin_addr.s_addr), addr_as_string, INET_ADDRSTRLEN);
    printf("Parent Accepted from %s\n", addr_as_string);

    return sockfd;
}

int createTunDevice()
{
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  
    tunfd = open("/dev/net/tun", O_RDWR);
    ioctl(tunfd, TUNSETIFF, &ifr);

    return tunfd;
}

void tunSelected(int tunfd, int sockfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    printf("Read %d bytes from TUN\n", len);
    len = SSL_write(ssl, &buff, len);
    if (len > 0) {
        printf("Wrote %d bytes to SSL tunnel\n", len);
    } else if (len == 0) {
        printf("Wrote 0 packets. Closing");
        exit(0);
    } else {
        CHK_SSL(len);
    }
}

int socketSelected (int tunfd, int sockfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];

    bzero(buff, BUFF_SIZE);
    int read_blocked;
    do  {
        read_blocked = 0;
        len = SSL_read(ssl,buff,BUFF_SIZE);
        int ssl_error;

        //check SSL errors
        // Source: http://www.past5.com/tutorials/2014/02/21/openssl-and-select/
        switch(ssl_error = SSL_get_error(ssl,len)){
            case SSL_ERROR_NONE:
                // Normal
                printf("Read %d bytes from SSL tunnel\n", len);
                len = write(tunfd, &buff, len);
                if (len == 0) {
                    printf("Wrote zero bytes to TUN\n");
                } else if (len < 0) {
                    perror("Bad write to TUN");
                } else {
                    printf("Wrote %d bytes to TUN\n", len);
                }
                
            break;
            
            case SSL_ERROR_ZERO_RETURN:		
                //connection closed by client, clean up
                printf("Server closed connection\n");
                SSL_shutdown(ssl);  SSL_free(ssl);
                exit (0);
            break;
            
            case SSL_ERROR_WANT_READ:
                //the operation did not complete, block the read
                read_blocked = 1;
            break;
            
            case SSL_ERROR_WANT_WRITE:
                //the operation did not complete
                fprintf(stderr, "SSL_ERROR_WANT_WRITE\n");
            break;
            
            case SSL_ERROR_SYSCALL:
                //some I/O error occured (could be caused by false start in Chrome for instance), disconnect the client and clean up
                perror("SSL_ERROR_SYSCALL\n");
                ERR_print_errors_fp(stderr);
                exit (2);
            break;
                            
            default:
                //some other error, clean up
                fprintf(stderr, "Other Read error\n");
                exit (4);
        }

    } while (SSL_pending(ssl) && !read_blocked);
    return 0;
}


int main(int argc, char *argv[])
{
    char *hostname = "yahoo.com";
    int port = 443;
    char *ip;

    if (argc > 1) hostname = argv[1];
    if (argc > 2) port = atoi(argv[2]);
    if (argc > 3) ip = argv[3];

    // make a in_addr to hold IP
    struct in_addr conf_ip;
    int res = inet_pton(AF_INET, ip, &conf_ip);
    if (res != 1) {
        perror("Configured IP Address is bad");
        exit(5);
    }
    
    if (argc != 4) {
        printf("Usage: hostname port ip\n");
    }

    /*----------------TLS initialization ----------------*/
    SSL *ssl   = setupTLSClient(hostname);

    /*----------------Create a TCP connection ---------------*/
    int sockfd = setupTCPClient(hostname, port);

    /*----------------TLS handshake ---------------------*/
    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl);
    CHK_SSL(err);
    printf("SSL connection is successful\n");
    printf ("SSL connection using %s\n", SSL_get_cipher(ssl));

    // Send IP
    SSL_write(ssl, &(conf_ip.s_addr), sizeof(struct in_addr));
    sleep(1);
    // Ask and send user/pass
    printf("Enter username, then enter, then enter password (not echoed), then enter:\n");
    char user[CREDENTIAL_LEN];
    char pass[CREDENTIAL_LEN];
    char *pass_varlen;
    bzero (&user, sizeof(char) * CREDENTIAL_LEN);
    bzero (&pass, sizeof(char) * CREDENTIAL_LEN);
    read(STDIN_FILENO, &user, CREDENTIAL_LEN - 1);
    pass_varlen = getpass("");
    strncpy(pass, pass_varlen, CREDENTIAL_LEN - 1);

    SSL_write(ssl, &user, CREDENTIAL_LEN);
    SSL_write(ssl, &pass, CREDENTIAL_LEN);

    sleep(1);
    // Check for authorization
    // strlen("Authorized.    \r\n"); = 17
    char auth[18];
    auth[17] = 0;
    SSL_read(ssl, &auth, 17);
    printf("%s\n", auth);

    int tunfd;

    tunfd  = createTunDevice();

    while (1) {
        fd_set readFDSet;
        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(tunfd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sockfd, ssl);
        if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd, ssl);
    }
}

