#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <termios.h>
#include <openssl/aes.h>
#include <errno.h>

struct ctr_state {
        unsigned char ivec[16];  
        unsigned int num;
        unsigned char ecount[16];
};

int init_ctr(struct ctr_state *state, const unsigned char iv[8])
{
        /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
         * first call. */
        state->num = 0;
        memset(state->ecount, 0, 16);

        /* Initialise counter in 'ivec' to 0 */
        memset(state->ivec + 8, 0, 8);

        /* Copy IV into 'ivec' */
        memcpy(state->ivec, iv, 8);
}

int debug = 0;



int main(int argc, char *argv[]){
        struct addrinfo hints;
        struct addrinfo *result, *rp;
        int cfd,sfd, s;	
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len;
        ssize_t nread;
        char *inboundPort = NULL;
        char *key = NULL;   
        int op;
        char *hostname = NULL;
        char *port = NULL;
        char *cmdLineOpts = "l:k:";
        ssize_t len;	
        ssize_t n;
        AES_KEY aes_key;
        unsigned char cipherkey[128];
        struct ctr_state state;  
        FILE *keyfile; 
        while((op = getopt(argc, argv, cmdLineOpts)) != -1){
                switch(op){
                        case 'l':
                                inboundPort = optarg;
                                break;
                        case 'k':
                                keyfile = fopen(optarg, "r");	
                                if(keyfile != NULL){
                                        fgets(cipherkey, 128, keyfile);
                                        fclose(keyfile);
                                }
                                break;
                }
        }
        if((argv[optind]!=NULL) && (argv[optind+1] != NULL)){
                hostname = argv[optind];
                port = argv[optind+1];	 	
        }
        else{
                printf("Error in arguments: missing hostname and destination port");
                exit(1);
        }	

        if(cipherkey == NULL){
                printf("No key given");
                exit(1);
        }
        if(debug)
                printf("\nkey %s\n",cipherkey); 

        /* getaddrinfo() returns a list of address structures.
           Try each address until we successfully bind(2).
           If socket(2) (or bind(2)) fails, we (close the socket
           and) try the next address. */
        if(inboundPort == NULL){
                /* CLIENT */
                int flags;
                struct termios oldt, newt;
                FILE *fp = fopen("log.txt", "w");
                ssize_t len;
                int incoming,i;
                fd_set readfds, writefds;
                unsigned char iv[8];//= {1};
                memset(&hints, 0, sizeof(struct addrinfo));
                hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
                hints.ai_socktype = SOCK_STREAM; /* Stream socket */
                hints.ai_flags = 0;    /* For wildcard IP address */
                hints.ai_protocol = 0;          /* Any protocol */

                s = getaddrinfo(hostname, port, &hints, &result);
                if (s != 0) {
                        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
                        exit(EXIT_FAILURE);
                }
                for (rp = result; rp != NULL; rp = rp->ai_next) {
                        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                        if (sfd == -1)
                                continue;
                        if(connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
                                break;
                        close(sfd);
                }
                if (rp == NULL) {               /* No address succeeded */
                        fprintf(stderr, "Could not bind\n");
                        exit(EXIT_FAILURE);
                }
                tcgetattr(STDIN_FILENO, &oldt);
                newt = oldt;
                newt.c_lflag &= ~(ICANON | ECHO);
                tcsetattr(STDIN_FILENO, TCSANOW, &newt);

                /* 
                   Non blocking IO used without select()
                   flags = fcntl(sfd, F_GETFL, 0);
                   fcntl(sfd, F_SETFL, flags | O_NONBLOCK);
                   flags = fcntl(STDIN_FILENO, F_GETFL, 0);
                   fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
                 */

                if (!RAND_bytes(iv, 8)){
                        fprintf(fp,"Error in random bytes");
                        exit(1);
                }
                if (debug){
                        for(i = 0; i<8;i++)
                                fprintf(fp,"%d: %02x\n", i, iv[i]);	
                }
                init_ctr(&state, iv);
                AES_set_encrypt_key(cipherkey, 128, &aes_key);
                FD_ZERO(&readfds);
                FD_SET(0, &readfds);
                FD_SET(sfd, &readfds);
                if(write(sfd, iv, 8) != 8){
                        fprintf( fp,"error in sending iv\n");
                        exit(1);
                }
                if (debug)
                        fprintf(fp,"before while select\n");
                // while(1){
                while(incoming = select(FD_SETSIZE, &readfds,NULL, NULL, NULL)){
                        ssize_t m;
                        static unsigned char to_server[256];
                        static unsigned char from_server[256];
                        static unsigned char from_server_encrypted[256];
                        static unsigned char to_server_encrypted[256];
                        if(debug){
                                fprintf(fp,"Reading from client\n");
                                fflush(fp);
                        }
                        //        incoming = select(FD_SETSIZE, &readfds, NULL, NULL, NULL);
                        if(incoming == -1){
                                perror("select");
                        }	
                        else if(FD_ISSET(0, &readfds)){
                                if((len = read(0, to_server, 255))>0){
                                        int t;
                                        to_server[len] = '\0';
                                        fprintf(fp,"Received from stdin %s %zd \n", to_server, len);
                                        fflush(fp);
                                        init_ctr(&state, iv);
                                        AES_set_encrypt_key(cipherkey, 128, &aes_key);
                                        AES_ctr128_encrypt(to_server, to_server_encrypted, len, &aes_key, state.ivec, state.ecount, &state.num);
                                        fprintf(fp,"at client, value of IV: %u, state parameters: %u %d %u\n", iv, state.ivec, state.ecount, state.num);
                                        for(t = 0; t < len; t++){
                                                fprintf(fp,"%02x", (unsigned char)(to_server_encrypted[t]));
                                        }
                                        fprintf(fp,"\n");
                                        if(debug){
                                                to_server_encrypted[len] = '\0';
                                                fprintf(fp,"encrypted to %s\n",to_server_encrypted);
                                                fflush(fp);
                                        }
                                        if(write(sfd, to_server_encrypted, len) != len){
                                                fprintf(fp,"couldnt write to server %s", to_server);
                                                fflush(fp);
                                        }else{
                                                fprintf(fp,"Sent to server %s len %d\n", to_server , len);
                                                fflush(fp);
                                        }
                                }
                        }
                        else if(FD_ISSET(sfd, &readfds)){
                                if((m = read(sfd, from_server_encrypted, 255))>0){
                                        if(debug){
                                                fprintf(fp,"Received from server len %d \n", m);
                                                fflush(fp);
                                        }
                                        init_ctr(&state, iv);
                                        AES_set_encrypt_key(cipherkey, 128, &aes_key);
                                        AES_ctr128_encrypt(from_server_encrypted, from_server, m, &aes_key, state.ivec, state.ecount, &state.num);
                                        from_server[m] = '\0';
                                        if(write(1, from_server, m) != m){
                                                fprintf(fp,"couldnt write to stdout %s", from_server);
                                                fflush(fp);
                                        }else{
                                                fprintf(fp, "Sent to stdout %s\n", from_server);
                                                fflush(fp);
                                        }
                                }
                        }
                        FD_SET(0, &readfds);
                        FD_SET(sfd, &readfds);
                }

                /* End of client */
        } else{  /* Server */
                struct addrinfo hintsSocket2;
                struct addrinfo *result2, *rp2;
                static unsigned char client_buf[256];
                static unsigned char client_buf_encrypted[256];
                static unsigned char service_buf[256];
                static unsigned char service_buf_encrypted[256];
                int lfd, d;	
                fd_set readfds, writefds;
                unsigned char iv[8];//= {1};
                memset(&hints, 0, sizeof(struct addrinfo));
                hints.ai_family = AF_UNSPEC;   
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_flags = AI_PASSIVE;    
                hints.ai_protocol = 0;          
                hints.ai_canonname = NULL;
                hints.ai_addr = NULL;
                hints.ai_next = NULL;
                FD_ZERO(&readfds);
                FD_ZERO(&writefds);
                s = getaddrinfo(NULL, inboundPort, &hints, &result);
                if (s != 0) {
                        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
                        exit(EXIT_FAILURE);
                }
                printf("Entering server mode");		
                memset(&hintsSocket2, 0, sizeof(struct addrinfo));
                hintsSocket2.ai_family = AF_UNSPEC;    
                hintsSocket2.ai_socktype = SOCK_STREAM; 
                hintsSocket2.ai_flags = 0;    
                hintsSocket2.ai_protocol = 0;          
                hintsSocket2.ai_canonname = NULL;
                hintsSocket2.ai_addr = NULL;
                hintsSocket2.ai_next = NULL;


                for (rp = result; rp != NULL; rp = rp->ai_next) {
                        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                        if (sfd == -1)
                                continue;
                        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
                                break;                  /* Success */
                        close(sfd);
                }


                if (rp == NULL) {               /* No address succeeded */
                        fprintf(stderr, "Could not bind\n");
                        exit(EXIT_FAILURE);
                }

                freeaddrinfo(result);           /* No longer needed */

                if(listen(sfd, 50) == -1){
                        printf("Error in listen");
                        exit(1);
                }	
                peer_addr_len = sizeof(struct sockaddr_storage);
                d = getaddrinfo(hostname, port, &hintsSocket2, &result2);
                if(d!=0){
                        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(d));
                        exit(EXIT_FAILURE);
                } 

                //freeaddrinfo(result2);
                while(1){
                        int t,incoming,flags, max;
                        ssize_t k;	
                        int i; char dump[16];
                        for (rp2 = result2; rp2 != NULL; rp2 = rp2->ai_next) {
                                lfd = socket(rp2->ai_family, rp2->ai_socktype, rp2->ai_protocol);
                                if (lfd == -1)
                                        continue;
                                if(connect(lfd, rp2->ai_addr, rp2->ai_addrlen) == 0)
                                        break;
                                close(lfd);
                        }	
                        if (rp2 == NULL) {            
                                fprintf(stderr, "Could not connect\n");
                                exit(EXIT_FAILURE);
                        }
                        if(debug)
                                printf("accepting\n");
                        cfd = accept(sfd, (struct sockaddr *) &peer_addr, &peer_addr_len);
                        FD_ZERO(&readfds);
                        FD_ZERO(&writefds);
                        FD_SET(cfd, &readfds);
                        FD_SET(cfd, &writefds);
                        FD_SET(lfd, &writefds);
                        FD_SET(lfd, &readfds);
                        if(cfd == -1){
                                printf("Error in cfd");
                                exit(1);
                        }
                        /* Unblocking IO
                           flags = fcntl(cfd, F_GETFL, 0);
                           fcntl(cfd, F_SETFL, flags | O_NONBLOCK);
                           flags = fcntl(lfd, F_GETFL, 0);
                           fcntl(lfd, F_SETFL, flags | O_NONBLOCK);
                         */
                        if (read(cfd, iv, 8)!=8)
                                printf("errpr in read iv\n");
                        if(debug){
                                for(i=0;i<8;i++)
                                        printf("IV: %02x\n", iv[i]);
                        }
                        max = ((cfd>lfd)?cfd:lfd);
                        init_ctr(&state, iv);
                        if(debug){
                                printf("cfd %d lfd %d max %d\n", cfd, lfd, max);
                        }
                        //while(1){
                        while(incoming = select(max+1, &readfds, NULL, NULL, NULL)){
                                ssize_t m;
                                if(debug)
                                        printf("Before select\n");
                                if(debug)
                                        printf("Incoming %d\n", incoming);
                                if(incoming == -1){
                                        perror("select");
                                }	
                                if(incoming == 0){
                                        printf("zero\n");
                                }	
                                else if(FD_ISSET(cfd, &readfds)){
                                        if((n = read(cfd, client_buf_encrypted, 255))>0){	
                                                //client_buf_encrypted[n] = '\0';
                                                if(debug)
                                                        printf("Received from client len %zd\n", n);
                                                init_ctr(&state, iv);
                                                AES_set_encrypt_key(cipherkey, 128, &aes_key);
                                                AES_ctr128_encrypt(client_buf_encrypted, client_buf, n, &aes_key, state.ivec, state.ecount, &state.num);
                                                if(debug){
                                                        printf("at server, value of IV: %u, state parameters: %u %d %u\n", iv, state.ivec, state.ecount, state.num);
                                                        printf("encrypted data: ");
                                                        for(t = 0; t <n; t++){
                                                                printf("%02x", (unsigned char)(client_buf_encrypted[t]));
                                                        }
                                                        printf("\n")    ;	
                                                        client_buf[n] = '\0';
                                                        printf("Received from client %s len %zd\n", client_buf, n);
                                                }//printf("Decrypted to %s", client_buf);
                                                if(write(lfd, client_buf, n) != n)
                                                        printf("couldnt write to service %s", client_buf);
                                                //else
                                                if(debug)
                                                        printf("Sent to service %s\n", client_buf);
                                        }
                                        else if (n == 0){
                                                if(debug)
                                                        printf("Client closed %d %s %d\n", errno, strerror(errno), n);
                                                close(lfd);
                                                break;
                                        }
                                }
                                else if(FD_ISSET(lfd, &readfds)){
                                        //printf("Reading from service\n");
                                        if((m = read(lfd, service_buf, 255))>0){
                                                if(debug){
                                                        service_buf[m] = '\0';
                                                        printf("Received from service  %s\n", service_buf);
                                                }
                                                init_ctr(&state, iv);
                                                AES_set_encrypt_key(cipherkey, 128, &aes_key);
                                                AES_ctr128_encrypt(service_buf, service_buf_encrypted, m, &aes_key, state.ivec, state.ecount, &state.num);
                                                if(write(cfd, service_buf_encrypted, m) != m)
                                                        printf("couldnt write to client %s", service_buf);
                                                else
                                                        if(debug)
                                                                printf("Sent to client %s %d\n", service_buf, m);
                                        }
                                        else if (m == 0){
                                                if(debug)
                                                        printf("server closed %d\n",m);
                                                close(cfd);
                                                break;
                                        }
                                }

                                FD_SET(cfd, &readfds);
                                FD_SET(lfd, &readfds);
                        }

                }
                }
        }



