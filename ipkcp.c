#include <stdio.h>

#ifdef _WIN32
// If compiling on Windows, this code won't run, so exit program.
int main(int argc, char*  argv[]) {
    fprintf(stderr, "Windows is not supported platform");
    exit(0);
}
#else
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>

#define BUFSIZE 1024 // Define buffer size for messages.

bool is_upd = false; // Boolean variable to keep track of UDP vs TCP mode.
int client_socket;  // Socket file descriptor for client.

/**
 * Function to handle TCP mode.
 * @param char* buf - the buffer to be used for sending/receiving data
 * @param int bytestx -  number of bytes to transmit
 * @param int bytesrx - number of bytes to receive
 * @return void
*/
void tcp(char* buf ,int bytestx, int bytesrx)
{
    bzero(buf, BUFSIZE); // Clear buffer.
    // While the user hasn't entered the "BYE" message, keep reading and sending messages.
    while (strcmp(buf, "BYE\n") != 0)
    {
        // Read message from user.
        bzero(buf, BUFSIZE);
        fgets(buf, BUFSIZE, stdin);
        // Send message to server.
        bytestx = (int) send(client_socket, buf, strlen(buf), 0);
        if (bytestx < 0)
            perror("ERROR in sendto");
        // Receive response message from server.
        bzero(buf, BUFSIZE);
        bytesrx = (int) recv(client_socket, buf, BUFSIZE, 0);
        if (bytesrx < 0)
            perror("ERROR in recvfrom");
        // Print server response message.
        printf("%s", buf);
    }
}

/**
 * Function to handle UPD mode.
 * @param char* buf - Pointer to the buffer to be sent.
 * @param int bytestx -  Number of bytes to be sent.
 * @param int bytesrx - Number of bytes to be received.
 * @param socklen_t serverlen - Size of the server address structure.
 * @param struct sockaddr_in server_address - Struct containing the server address 
 * @return void
*/
void upd(char* buf, int bytestx, int bytesrx, socklen_t serverlen, struct sockaddr_in server_address)
{
    while(1)
    {
        char buf_exp[BUFSIZE];

        // Read message from user.
        bzero(buf, BUFSIZE);
        if (fgets(buf_exp, BUFSIZE, stdin) == NULL) {
            break;
        }

        // Construct message to be sent to server (consists of a header byte and the actual message).
        buf[0] = 0x0;
        buf[1] = strlen(buf_exp);
        memcpy(buf + 2, buf_exp, strlen(buf_exp) + 1);

        // Send message to server.
        serverlen = sizeof(server_address);
        bytestx = (int) sendto(client_socket, buf, strlen(buf_exp) + 2, 0, (struct sockaddr *) &server_address, serverlen);
        if (bytestx < 0)
            perror("ERROR: sendto");

        bzero(buf, BUFSIZE);
        // Receive response message from server.
        bytesrx = (int) recvfrom(client_socket, buf, BUFSIZE, 0, (struct sockaddr *) &server_address, &serverlen);
        
        // Parse response message and print appropriately.
        if (bytesrx < 0) {perror("ERROR: recvfrom");}

        if(buf[1] == 0x0)
        {
            buf = buf + 3;
            printf("OK: %s\n", buf);
        }
        else if (buf[1] == 0x1)
        {
            fprintf(stderr, "ERR: %s", buf);
        }
        else
        {
            perror("Unexpected response message\n");
        }
    }
}

void ctrl_c() {
    char buffer[BUFSIZE];
    bzero(buffer, BUFSIZE); // Clear buffer

    if (client_socket > 0) {
        if (!is_upd) { // If TCP
            strcpy(buffer, "BYE\n"); // Set message to "BYE\n"
            send(client_socket, buffer, 4, 0); // Send "BYE\n" to server
            printf("\n");
            printf("%s", buffer); // Print "BYE\n" to console
            recv(client_socket, buffer, BUFSIZE, 0);  // Receive message from server
            printf("%s", buffer); // Print message from server to console
            
        }
        close(client_socket); // close socket
    }
    exit(EXIT_SUCCESS); // exit
}

int main (int argc, const char * argv[]) {
    int port_number, bytestx = -1, bytesrx = -1;
    socklen_t serverlen = -1;
    const char *server_hostname;
    struct hostent *server;
    struct sockaddr_in server_address;
    char buf[BUFSIZE];
    bzero(buf, BUFSIZE); // clear buffer

    signal(SIGINT, &ctrl_c); // handle SIGINT Ctrl+C

    /* 1. Test input parameters: */
    if (argc != 7)
    {
        fprintf(stderr,"usage: %s -h <hostname> -p <port> -m <mode>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    if(strcmp(argv[1],"-h")==0) {server_hostname = argv[2];} // Set server hostname
    else
    {
        fprintf(stderr,"usage: %s -h <hostname> -p <port> -m <mode>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    if(strcmp(argv[3],"-p")==0){port_number = atoi(argv[4]);} // Set server port number
    else
    {
        fprintf(stderr,"usage: %s -h <hostname> -p <port> -m <mode>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    if(strcmp(argv[5],"-m")==0)
    {
        if(strcmp(argv[6],"udp") == 0) {is_upd = true;} // If mode is UDP, set flag to true
        else if (strcmp(argv[6],"tcp") == 0) {is_upd = false;} // If mode is TCP, set flag to false
        else
        {
          fprintf(stderr,"Unknown mode: %s tcp or udp\n", argv[0]);
          exit(EXIT_FAILURE);
        }
    }
    else
    {
        fprintf(stderr,"usage: %s -h <hostname> -p <port> -m <mode>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if(port_number < 0 || port_number > 65536)
    {
        fprintf(stderr,"ERROR: Port must be in interval 0-65536,not %d\n", port_number); // Print error message for invalid port number
        exit(EXIT_FAILURE);
    }

     /* 2. Get server address using DNS */

    if ((server = gethostbyname(server_hostname)) == NULL)
    {
        fprintf(stderr,"ERROR: no such host as %s\n", server_hostname); // Print error message if server hostname cannot be found
        exit(EXIT_FAILURE);
    }

     /* 3. Find server IP address and initialize server_address struct */
    bzero((char *) &server_address, sizeof(server_address));// Clear server_address
    server_address.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_address.sin_addr.s_addr, server->h_length);
    server_address.sin_port = htons(port_number);

   /*Printing information about the remote socket.*/
    printf("INFO: Server socket: %s : %d \n", inet_ntoa(server_address.sin_addr), ntohs(server_address.sin_port));

    /* Creating a socket. */
    if (!is_upd)
    {
        client_socket = socket(AF_INET, SOCK_STREAM, 0);
    }
    else
    {
        client_socket = socket(AF_INET, SOCK_DGRAM, 0);
    }
    
    /*Checking if the socket was created successfully.*/

    if (client_socket <= 0)
    {
        perror("ERROR: socket");
        exit(EXIT_FAILURE);
    }
    
    /*Connecting to the server.*/
    if (connect(client_socket, (const struct sockaddr *) &server_address, sizeof(server_address)) != 0)
    {
        perror("ERROR: connect");
        exit(EXIT_FAILURE);
    }
    
    /*Performing TCP or UDP communication based on the value of is_upd.*/
    if (!is_upd)
    {
        tcp(buf,bytestx,bytesrx);
    }
    else
    {
        upd(buf,bytestx,bytesrx,serverlen,server_address);
    }

    close(client_socket); //Closing the socket.
    return 0; //Returning 0 to indicate success.
}
#endif