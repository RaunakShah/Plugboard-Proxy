Test environment:

LSB Version:    :core-3.1-amd64:core-3.1-ia32:core-3.1-noarch:graphics-3.1-amd64:graphics-3.1-ia32:graphics-3.1-noarch
Distributor ID: CentOS
Description:    CentOS release 5.2 (Final)
Release:        5.2
Codename:       Final
Linux 2.6.18-238.19.1.el5xen x86_64


Compiler:
gcc (GCC) 4.1.2 20071124 (Red Hat 4.1.2-42)


To compile:
       make pbproxy

To run server:
        ./pbproxy -k <keyfile> -l <port1> <destination> <port2>
        ./pbproxy -k keyfile.txt -l 12345 localhost 22

To run client:
        ./pbproxy -k <keyfile> <destination> <port1>
        ssh -o "ProxyCommand ./pbproxy -k keyfile.txt localhost 12345"
        localhost 


Description:
pbproxy runs in two modes: client and server. The program detects which mode
to run in by the presence/absence of -l option. 
In server mode, pbproxy waits for a client connection, and opens one socket to
the client and one to the intended service. it accepts messages from client
and decrypts them before forwarding to the service. similarly it encrypts
messages from the service before forwarding to client. i have used the select() calls to
detect whether there is available input in the read buffer from either socket.
On termination, pbproxy resumes waiting for a connection by a client and
repeats the process. 
in client mode, the client connects to an open port where a pbproxy server is
being run. any message to be sent to the service are encrypted and sent to
pbproxy server. before any communication of messages takes place, the client
generates a random IV and sends the IV as plaintext to the pbproxy server.


References:
socket creation - Man pages, especially http://man7.org/linux/man-pages/man3/getaddrinfo.3.html 
encryption/decryption -
https://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl
and openssl man pages

