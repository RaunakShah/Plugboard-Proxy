# Plugboard Proxy

Adds an extra layer of protection to publicly accessible network services

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



