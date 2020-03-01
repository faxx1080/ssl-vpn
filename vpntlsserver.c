#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <shadow.h>
#include <crypt.h>
#include <signal.h>

volatile sig_atomic_t exit_now = 0;

#define CHK_SSL(err) if ((err) < 1) { \
    perror("Error"); \
    int macro_sslerr = SSL_get_error(ssl, err); \
    fprintf(stderr, "SSL ERROR %d\n", macro_sslerr); \
    ERR_print_errors_fp(stderr); \
    exit(2); \
}
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define MAX_CLIENTS 5
#define BUFF_SIZE 2000
#define CREDENTIAL_LEN 256

// volatile sig_atomic_t child_pids[] = sig_atomic_t[MAX_CLIENTS];

void signal_handler(int signal)
{
    exit_now = 1;
}

int  setupTCPServer();                   // Defined in Listing 19.10
void processRequest(SSL* ssl, int sock); // Defined in Listing 19.12

int login(char *user, char *passwd)
{
    struct spwd *pw;
    char *epasswd;

    pw = getspnam(user);
    if (pw == NULL) {
        return -1;
    }
    epasswd = crypt(passwd, pw->sp_pwdp);
    int res = strcmp(epasswd, pw->sp_pwdp);
    if (res == 0) {
        return 1;
    }
    printf("Bad\n");
    return -1;
}

/*
void sigchildhandle(int signum) {
    int wstat;
    union wait wstat;
    pid_t	pid;

    while (TRUE) {
        pid = wait3 (&wstat, WNOHANG, (struct rusage *)NULL );
        if (pid == 0)
            return;
        else if (pid == -1)
            return;
        else {
            printf ("Child Return code: %d\n", wstat.w_retcode);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (child_pids[i] == pid) {
                    child_pids[i] = -1
                }
            }
        }
    }

}
*/

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

int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (4433);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

int childProcess(SSL* ssl, int sock, int parent_pipe_fd, int tunfd, int curr_client_no) {
    SSL_set_fd (ssl, sock);
    int err = SSL_accept (ssl);
    CHK_SSL(err);
    printf ("SSL connection established!\n");

    in_addr_t conf_ip;
    char user[CREDENTIAL_LEN];
    char pass[CREDENTIAL_LEN];
    bzero (&user, sizeof(char) * CREDENTIAL_LEN);
    bzero (&pass, sizeof(char) * CREDENTIAL_LEN);

    // Read IP addr so this child knows when to send.
    SSL_read(ssl,&conf_ip,sizeof(in_addr_t));

    // Read User & pass as user\r\npass\r\n.
    SSL_read(ssl,&user,CREDENTIAL_LEN);
    SSL_read(ssl,&pass,CREDENTIAL_LEN);

    // Crop off \n
    user[strlen((const char *)&user) - 1] = 0;
    pass[strlen((const char *)&pass)] = 0;
    
    int authorized = login(user, pass);
    if (authorized == 1) {
        fprintf(stderr, "Child %d - Access Granted. User: %s\n", curr_client_no, user);
        SSL_write(ssl, "Authorized.    \r\n", strlen("Authorized.    \r\n"));
    } else {
        fprintf(stderr, "Child %d - Access Denied. User: %s\n", curr_client_no, user);
        SSL_write(ssl, "Not Authorized.\r\n", strlen("Not Authorized.\r\n"));
        SSL_shutdown(ssl);  SSL_free(ssl); 
        return 1;
    }
    
    int  len;
    char buff[BUFF_SIZE];
    char addr_as_string[INET_ADDRSTRLEN];
    int read_blocked = 0;

    inet_ntop(AF_INET, &conf_ip, addr_as_string, INET_ADDRSTRLEN);
    printf ("Handled IP: %s\n", addr_as_string);

    while (1) {

        bzero(buff, BUFF_SIZE);
        

        // Need to select on sock & pipe.
        fd_set readFDSet;
        FD_ZERO(&readFDSet);
        FD_SET(sock, &readFDSet);
        FD_SET(parent_pipe_fd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        if (FD_ISSET(sock,  &readFDSet)) {
            // need to check for SSL errors
            // Source: http://www.past5.com/tutorials/2014/02/21/openssl-and-select/
            do  {
                read_blocked = 0;
                int len = SSL_read(ssl,buff,BUFF_SIZE);
                printf("SSL_read returned %d for Child %d\n", len, curr_client_no);
                int ssl_error;

                //check SSL errors
                switch(ssl_error = SSL_get_error(ssl,len)){
                    case SSL_ERROR_NONE:
                        // Normal
                        printf("Read %d bytes from SSL tunnel for Child %d\n", len, curr_client_no);
                        len = write(tunfd, &buff, len);
                        if (len == 0) {
                            printf("Wrote zero bytes to TUN for Child %d\n", curr_client_no);
                        } else if (len < 0) {
                            fprintf(stderr, "Bad Write to TUN for child %d ", curr_client_no);
                            perror("Bad write to TUN");
                        } else {
                            printf("Wrote %d bytes to TUN for Child %d\n", len, curr_client_no);
                        }
                    break;
                    
                    case SSL_ERROR_ZERO_RETURN:		
                        //connection closed by client, clean up
                        printf("Client closed connection - child %d\n", curr_client_no);
                        SSL_shutdown(ssl);  SSL_free(ssl);
                        return 0;
                    break;
                    
                    case SSL_ERROR_WANT_READ:
                        //the operation did not complete, block the read
                        read_blocked = 1;
                    break;
                    
                    case SSL_ERROR_WANT_WRITE:
                        //the operation did not complete
                        fprintf(stderr, "SSL_ERROR_WANT_WRITE - client %d\n", curr_client_no);
                    break;
                    
                    case SSL_ERROR_SYSCALL:
                        //some I/O error occured (could be caused by false start in Chrome for instance), disconnect the client and clean up
                        fprintf(stderr, "SSL_ERROR_SYSCALL - client %d\n", curr_client_no);
                        ERR_print_errors_fp(stderr);
                        perror("Syscall error");
                        return 2;
                    break;
                                    
                    default:
                        //some other error, clean up
                        fprintf(stderr, "Other Read error - client %d\n", curr_client_no);
                        return 4;
                }

            } while (SSL_pending(ssl) && !read_blocked);
        }

        if (FD_ISSET(parent_pipe_fd, &readFDSet)) {
            // Just forward along
            // Wrong, only read the actual length set.
            int supposed_to_read;
            len = read(parent_pipe_fd, (char*)&supposed_to_read, 4);
            len = read(parent_pipe_fd, buff, supposed_to_read);
            printf("Read %d bytes from parent for Child %d\n", len, curr_client_no);

            // len = read(tunfd, buff, BUFF_SIZE);
            // need to send to child. But which one?
            // bytes 30-33
            if (len < 0) {
                perror("Bad Read, quitting.");
                return -1;
            }
            if (len < 34) {
                // IPv4 header not present, bail.
                printf("IPv4 Header not found, dropping packet.\n");
                return 0;
            }
            in_addr_t dst_ip = *(in_addr_t*)(buff + 16); // please don't hate me!
                                            // Take 4 bytes starting at byte 30; read as int.
                                            // no, we're not checking the checksum.
            inet_ntop(AF_INET, &dst_ip, addr_as_string, INET_ADDRSTRLEN);
            printf("DST: %s\n", addr_as_string);

            if (conf_ip != dst_ip) {
                printf("Wrong child.\n");
                continue;
            }

            int ret = SSL_write(ssl, &buff, len);
            
            if (ret > 0) {
                // no error
                printf("Wrote %d bytes to SSL tunnel for child %d\n", ret, curr_client_no);
            } else if (ret == 0) {
                // error, likely close/shutdown
                SSL_shutdown(ssl);  SSL_free(ssl);
                break;
            } else {
                // error, die
                exit(1);
            }

        }
    }
    return 0;
}

// Two locations we can read from: SSL connection & TUN.
// if from SSL, then send to TUN.
// if from TUN then send to SSL.

// From tun0 -> SSL
int tunSelected(SSL* ssl, int tunfd, struct sockaddr_in *client_addrs, int curr_client_no, int pipe_fd_children[MAX_CLIENTS][2]){
    // The hard one.
    int  len;
    char buff[BUFF_SIZE];
    char addr_as_string[INET_ADDRSTRLEN];

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    // need to send to child. But which one?
    // bytes 30-33
    if (len < 0) {
        perror("Bad Read, quitting.");
        return -1;
    }
    if (len < 34) {
        // IPv4 header not present, bail.
        perror("IPv4 Header not found, dropping packet.\n");
        return 0;
    }

    in_addr_t dst_ip = *(in_addr_t*)(buff + 16); // please don't hate me!
                                     // Take 4 bytes starting at byte 30; read as int.
                                     // no, we're not checking the checksum.
    inet_ntop(AF_INET, &dst_ip, addr_as_string, INET_ADDRSTRLEN);
    printf("Parent DST: %s\n", addr_as_string);
    if (strncmp("192.168.5",addr_as_string,9) != 0) {
        printf("   Bad Packet.\n");
        //return 0;
    }
    printf("Parent Got %d bytes from TUN\n", len);

    for (int i = 0; i < curr_client_no; i++) {
        //inet_ntop(AF_INET, &client_addrs[i].sin_addr.s_addr, addr_as_string, INET_ADDRSTRLEN);
        //printf("Potential: %s\n", addr_as_string);
        //if (client_addrs[i].sin_addr.s_addr == dst_ip) {
            //printf("Packet for child %d", i);
            // found it!
            char size_of_write[4];
            memcpy(size_of_write, (char*)&len, sizeof(char) * 4);
            int res = write(pipe_fd_children[i][1], &size_of_write, 4);
            res = write(pipe_fd_children[i][1], &buff, len);
            if (res < 0) {
                // failed
                if (errno == EBADF) {
                    continue;
                }
                if (errno == EPIPE) {
                    // we ignore this error, means a child closed out.
                    continue;
                } else {
                    fprintf(stderr, "Write to child %d - ", i);
                    perror("Write failed");
                    return 1;
                }
                
            } else {
                printf("Write to pipe for child %d\n", i);
            }
        //}
    }
    // fprintf(stderr, "Client not found, dropping packet\n");
    return 0;
}


int main(){
    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL *ssl;
    // int err;
    int curr_client_no = 0;

    // To handle Ctrl-C
    signal(SIGTERM, signal_handler);

    // To silence sigpipe
    signal(SIGPIPE, SIG_IGN);

    /*
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
        perror(0);
        exit(1);
    }
    */

    int pipe_fds[MAX_CLIENTS][2];

    int tunfd;
    struct sockaddr_in client_addrs[MAX_CLIENTS];
    struct sockaddr_in client1;

    memset(&client_addrs, 0, sizeof(struct sockaddr_in) * MAX_CLIENTS);
    memset(&client1, 0, sizeof(struct sockaddr_in));
    size_t client_lengths[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_lengths[i] = sizeof(struct sockaddr_in);
    }

    tunfd = createTunDevice();

    // Step 0: OpenSSL library initialization 
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    // Step 1: SSL context initialization
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    // Step 2: Set up the server certificate and private key
    SSL_CTX_use_certificate_file(ctx, "./cert_server/mig_cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/mig_key.pem", SSL_FILETYPE_PEM);
    // Step 3: Create a new SSL structure for a connection
    ssl = SSL_new (ctx);

    // struct sockaddr_in sa_client;
    // size_t client_len;
    int listen_sock = setupTCPServer();
    int do_listen = 1;
    while (1) {
        if (exit_now) {
            exit (0);
        }
        if (do_listen == 0 || curr_client_no >= MAX_CLIENTS) {
            do_listen = 0;
            close(listen_sock);
        }

        fd_set readFDSet;
        FD_ZERO(&readFDSet);
        if (do_listen == 1) {
            FD_SET(listen_sock, &readFDSet);
            printf("Parent Listening\n");
        } else {
            printf("Waiting For Packets\n");
        }
        FD_SET(tunfd, &readFDSet);
        

        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        if (FD_ISSET(listen_sock,  &readFDSet)) {
            struct sockaddr_in* currclient = &client_addrs[MAX_CLIENTS];
            int sock = accept(listen_sock, (struct sockaddr*)currclient, &client_lengths[curr_client_no]);
            char addr_as_string[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(currclient->sin_addr).s_addr, addr_as_string, INET_ADDRSTRLEN);
            printf("Parent Accepted from %s\n", addr_as_string);
            
            // only make pipes as needed
            if (pipe(pipe_fds[curr_client_no]) == -1) {
                perror("pipe");
                exit(1);
            }
            pid_t child_pid = fork();
            if (child_pid == 0) { // The child process
                close(listen_sock);
                // close other child pipes
                for (int i = 0; i < curr_client_no; i++) {
                    printf("Close pipe %d in child %d\n", i, curr_client_no);
                    // close(pipe_fds[i][0]);
                    close(pipe_fds[i][1]);
                }
                close(pipe_fds[curr_client_no][1]);
                int exitVal = childProcess(ssl, sock, pipe_fds[curr_client_no][0], tunfd, curr_client_no); // returns on close, exits on fail.
                printf("Client %d exited.\n", curr_client_no);
                return exitVal;
            } else { // The parent process
                // child_pids[curr_client_no] = child_pid;
                close(pipe_fds[curr_client_no][0]);
                curr_client_no++;
                close(sock);
                continue;
            }
        }

        if (FD_ISSET(tunfd, &readFDSet)) {
            // We need to find out what child to send to, which means
            // look at DST ip
            // match (O(n)) with client_addrs
            // We cannot figure out yet if a child exited, so addrs can't be reused without a full exit.
            int ret = tunSelected(ssl, tunfd, client_addrs, curr_client_no, pipe_fds);
            if (ret < 0) {
                exit(1);
            }
        }
    }
}
