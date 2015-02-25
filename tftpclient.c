//==============================================================================
//
//          tftpclient.c
//
//==============================================================================
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "tftp.h"

// Global Variables
unsigned short current_block;
int current_state;
File_Container * transfer_file;

char * filename = NULL;

// Function prototypes
void process_message(char * message, int n, int sock_fd, struct sockaddr * addr);
int process_cl_args(int argc, char *argv[]);

//================================================================================
//
//  main
//
//================================================================================
void main(int argc, char *argv[])
{
    unsigned short client_op;

    int sock_fd;
    int bytes_received;
    char message[MESSAGE_SIZE];
    char file_op;

    struct sockaddr_in serv_addr, cli_addr;
    Packet * packet = NULL;

    client_op = process_cl_args(argc, argv);

    // Display init message
    printf("Group #06 Client\n");
    printf("Members: James Mack\n");
    printf("===================\n\n");

    // Create local socket
    sock_fd = setup_socket(INADDR_ANY, 0);
    current_state = STATE_READY;

    // Setup destination address
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);
    serv_addr.sin_port        = htons(SERVER_PORT);

    // Setup request message
    packet = Packet_init(client_op);
    RWRQ_Packet_construct(packet, client_op, filename, MODE);
    Packet_set_message(packet);

    // Send request message to server
    send_packet(packet, sock_fd, (struct sockaddr *) &serv_addr);
    current_block = 0;

    // Set state STATE_REQUEST_SENT
    current_state = STATE_REQUEST_SENT;

    free(packet);
    packet = NULL;

    // Setup transfer file
    
    if(client_op == OP_RRQ) {
        file_op = 'a';
    }
    else if(client_op == OP_WRQ) {
        file_op = 'r';
    }
    transfer_file = file_open(filename, file_op);

    // Receive response from server
    while(current_state != STATE_COMPLETE) {

        bytes_received = recvfrom(sock_fd, message, MESSAGE_SIZE, 0, NULL, NULL);

        if(bytes_received < 0) {
            printf("recvfrom error\n");
            exit(3);
        }
        else {
            process_message(message, bytes_received, sock_fd, (struct sockaddr *) &serv_addr);
        }
    }

    close(sock_fd);
    exit(0);
}

//================================================================================
//
//  process_cl_args
//
//================================================================================
int process_cl_args(int argc, char *argv[])
{
    int opt, opcode;
    opterr = 0;

    // Process command line arguments
    while ((opt = getopt (argc, argv, "r:w:")) != -1) {
        switch(opt) {
            case 'r':
                opcode = OP_RRQ;
                filename = optarg;
                break;
            case 'w':
                opcode = OP_WRQ;
                filename = optarg;
                break;
            case '?':
                if(optopt == 'r') {
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                }
                else if(optopt == 'w') {
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                }
                else if(isprint(optopt)) {
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                }
                else {
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                }
                exit(0);
                break;
        }
    }

    return opcode;
}


