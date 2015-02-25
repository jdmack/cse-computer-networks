//==============================================================================
//
//          tftpserver.c
//
//==============================================================================
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tftp.h"

// Global Variables
unsigned short current_block;
int current_state;
File_Container * transfer_file;

// Function prototypes
void process_message(char * message, int n, int sock_fd, struct sockaddr * addr);

//================================================================================
//
//  main
//
//================================================================================
void main(int argc, char *argv[])
{
    int  sock_fd;
    int  bytes_received; 
    char message[MESSAGE_SIZE];
    int  clilen;

    struct sockaddr * cli_addr;

    // Display init message
    printf("Group #06 Server\n");
    printf("Members: James Mack\n");
    printf("===================\n\n");

    // Create local socket
    sock_fd = setup_socket(INADDR_ANY, SERVER_PORT);
    current_state = STATE_READY;

    clilen = sizeof(struct sockaddr);

    // Main loop
    while(1) {

        bytes_received = recvfrom(sock_fd, message, MESSAGE_SIZE, 0, cli_addr, &clilen);

        if(bytes_received < 0) {
            printf("recvfrom error\n");
            exit(3);
        }
        else {
            process_message(message, bytes_received, sock_fd, cli_addr);
            if(current_state == STATE_COMPLETE) {
                current_state = STATE_READY;
            }
        }

    }
}
