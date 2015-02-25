//==============================================================================
//
//          tftp.c
//
//==============================================================================

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <errno.h>

#include "tftp.h"

//================================================================================
//
//  Packet_init 
//
//  Initializes a Packet struct to all zeroes.
//
//================================================================================
Packet * Packet_init(unsigned short opcode)
{
    if(DEBUG) fprintf(DEBUG_STREAM, "\t[DEBUG] Packet_init(%02u)\n", opcode);
    Packet * packet = NULL;

    switch(opcode) {
        case 1:
        case 2:
            packet = (Packet *) malloc(sizeof(RWRQ_Packet));
            memset(packet, 0, sizeof(RWRQ_Packet));
            break;
        case 3:
            packet = (Packet *) malloc(sizeof(DATA_Packet));
            memset(packet, 0, sizeof(DATA_Packet));
            break;
        case 4:
            packet = (Packet *) malloc(sizeof(ACK_Packet));
            memset(packet, 0, sizeof(ACK_Packet));
            break;
        case 5:
            packet = (Packet *) malloc(sizeof(ERROR_Packet));
            memset(packet, 0, sizeof(ERROR_Packet));
            break;
        default:
            break;
    }

    return packet;
}

//================================================================================
//
//  Packet_set_message 
//
//================================================================================
void Packet_set_message(Packet * packet)
{
    int offset;
    *(unsigned short *)&(packet->message) = htons(packet->opcode);
    if(DEBUG) fprintf(DEBUG_STREAM, "\t[DEBUG] Packet_set_message(%02u)\n", packet->opcode);
    
    switch(packet->opcode) {
        case 1:
        case 2:
            memcpy(&packet->message[2], ((RWRQ_Packet *)packet)->filename, sizeof(((RWRQ_Packet *)packet)->filename) + 1);
            offset = sizeof(packet->opcode) + strlen(((RWRQ_Packet *) packet)->filename) + 1;
            if(DEBUG) {
                printf("\t\toffset: %d\n", offset);
                printf("\t\tsizeof(packet->opcode): %d\n", sizeof(packet->opcode));
                printf("\t\tstrlen(packet->filename: %d\n", strlen(((RWRQ_Packet *) packet)->filename));
            }
            memcpy(&packet->message[offset], ((RWRQ_Packet *)packet)->mode, sizeof(((RWRQ_Packet *)packet)->mode) + 1);
            break;
        case 3:
            *(unsigned short *)&(packet->message[2]) = htons(((DATA_Packet *)packet)->block_num);
            memcpy(&packet->message[4], ((DATA_Packet *)packet)->data, sizeof(((DATA_Packet *)packet)->data));
            break;
        case 4:
            *(unsigned short *)&(packet->message[2]) = htons(((ACK_Packet *)packet)->block_num);
            break;
        case 5:
            break;
        default:
            break;
    }
}

//================================================================================
//
//  Packet_display_string
//
//================================================================================
char * Packet_display_string(Packet * packet, char * string)
{
    switch(packet->opcode) {
        case 1:
            sprintf(string, "RRQ\tfilename: %s\tsize: %d", ((RWRQ_Packet *)packet)->filename, packet->size);
            break;
        case 2:
            sprintf(string, "WRQ\tfilename: %s\tsize: %d", ((RWRQ_Packet *)packet)->filename, packet->size);
            break;
        case 3:
            sprintf(string, "DATA\tblock #: %d\t\tsize: %d", ((DATA_Packet *)packet)->block_num, packet->size);
            break;
        case 4:
            sprintf(string, "ACK\tblock #: %d\t\tsize: %d", ((ACK_Packet *)packet)->block_num, packet->size);
            break;
        case 5:
            sprintf(string, "ERROR\terror_code: %d\terror_message: %s\t\tsize: %d", ((ERROR_Packet *)packet)->error_code, ((ERROR_Packet *)packet)->error_message, packet->size);
            break;
        default:
            break;
    }

    return string;
}

//================================================================================
//
//  RWRQ_Packet_construct 
//
//================================================================================
void RWRQ_Packet_construct_msg(Packet * packet, unsigned short opcode, char * message)
{
    char * filename;
    char * mode;

    filename = read_message_filename(message);
    mode = read_message_mode(message, strlen(filename));

    packet->opcode = opcode;        
    strcpy(((RWRQ_Packet *) packet)->filename, filename);
    strcpy(((RWRQ_Packet *) packet)->mode, mode);
    strcpy(packet->message, message);
    packet->size = sizeof(packet->opcode) + strlen(((RWRQ_Packet *) packet)->filename) + strlen(((RWRQ_Packet *) packet)->mode) + 1 + 1;
    if(DEBUG) {
        fprintf(DEBUG_STREAM, "\t[DEBUG] Creating RWRQ_Packet\tsize: %d\n", packet->size);
        printf("\t\topcode:\t\t%02u\tsize: %d\n", opcode, sizeof(opcode));
        printf("\t\tfilename:\t%s\tsize: %d\n", filename, strlen(filename));
        printf("\t\tmode:\t\t%s\tsize: %d\n", mode, strlen(mode));
    }

    free(filename);
    free(mode);
}

void RWRQ_Packet_construct(Packet * packet, unsigned short opcode, char * filename, char * mode)
{
    packet->opcode = opcode;        
    strcpy(((RWRQ_Packet *) packet)->filename, filename);
    strcpy(((RWRQ_Packet *) packet)->mode, mode);
    packet->size = sizeof(opcode) + strlen(filename) + strlen(mode) + 1 + 1;

    if(DEBUG) {
        fprintf(DEBUG_STREAM, "\t[DEBUG] Creating RWRQ_Packet\tsize: %d\n", packet->size);
        printf("\t\topcode:\t\t%02u\tsize: %d\n", opcode, sizeof(opcode));
        printf("\t\tfilename:\t%s\tsize: %d\n", filename, strlen(filename));
        printf("\t\tmode:\t\t%s\tsize: %d\n", mode, strlen(mode));
    }
}

//================================================================================
//
//  DATA_Packet_construct 
//
//================================================================================

void DATA_Packet_construct_msg(Packet * packet, unsigned short opcode, char * message, int data_size)
{

    unsigned short block_num;
    char * data;

    packet->opcode = opcode;        
    block_num = read_message_block_num(message);
    data = read_message_data(message, data_size);

    ((DATA_Packet *) packet)->block_num = block_num;
    memcpy(((DATA_Packet *) packet)->data, data, data_size);

    packet->size = sizeof(opcode) + sizeof(((DATA_Packet *) packet)->block_num) + data_size;

    if(DEBUG) {
        fprintf(DEBUG_STREAM, "\t[DEBUG] Creating DATA_Packet\tsize: %d\n", packet->size);
        printf("\t\topcode:\t\t%02u\tsize: %d\n", opcode, sizeof(opcode));
        printf("\t\tblock_num:\t%02u\tsize: %d\n", block_num, sizeof(opcode));
        printf("\t\tdata:\t\t\tsize: %d\n%s\n", data_size, data);
    }

    free(data);
}

void DATA_Packet_construct(Packet * packet, unsigned short opcode, unsigned short b_num, char * data, int data_size)
{
    packet->opcode = opcode;        
    ((DATA_Packet *) packet)->block_num = b_num;
    memcpy(((DATA_Packet *) packet)->data, data, data_size);

    packet->size = sizeof(opcode) + sizeof(((DATA_Packet *) packet)->block_num) + data_size;

    if(DEBUG) {
        fprintf(DEBUG_STREAM, "\t[DEBUG] Creating DATA_Packet\tsize: %d\n", packet->size);
        printf("\t\topcode:\t\t%02u\tsize: %d\n", opcode, sizeof(opcode));
        printf("\t\tblock_num:\t%02u\tsize: %d\n", b_num, sizeof(opcode));
        printf("\t\tdata:\t\t\tsize: %d\n%s\n", data_size, data);
    }
}

//================================================================================
//
//  ACK_Packet_construct 
//
//================================================================================
void ACK_Packet_construct_msg(Packet * packet, unsigned short opcode, char * message)
{
    unsigned short block_num;

    block_num = read_message_block_num(message);

    packet->opcode = opcode;        
    ((ACK_Packet *) packet)->block_num = block_num;

    packet->size = sizeof(opcode) + sizeof(((DATA_Packet *) packet)->block_num);

    if(DEBUG) {
        fprintf(DEBUG_STREAM, "\t[DEBUG] Creating ACK_Packet\tsize: %d\n", packet->size);
        printf("\t\topcode:\t\t%02u\tsize: %d\n", opcode, sizeof(opcode));
        printf("\t\tblock_num:\t%02u\tsize: %d\n", block_num, sizeof(opcode));
    }
}

void ACK_Packet_construct(Packet * packet, unsigned short opcode, unsigned short b_num)
{
    packet->opcode = opcode;        
    ((ACK_Packet *) packet)->block_num = b_num;

    packet->size = sizeof(opcode) + sizeof(((DATA_Packet *) packet)->block_num);

    if(DEBUG) {
        fprintf(DEBUG_STREAM, "\t[DEBUG] Creating ACK_Packet\tsize: %d\n", packet->size);
        printf("\t\topcode:\t\t%02u\tsize: %d\n", opcode, sizeof(opcode));
        printf("\t\tblock_num:\t%02u\tsize: %d\n", b_num, sizeof(opcode));
    }
}

//================================================================================
//
//  ERROR_Packet_construct 
//
//================================================================================
void ERROR_Packet_construct_msg(Packet * packet, unsigned short opcode, char * message)
{
    unsigned short error_code;
    char * error_msg;

    error_code = read_message_error_code(message);
    error_msg = read_message_error_msg(message);

    packet->opcode = opcode;        
    ((ERROR_Packet *)packet)->error_code = error_code;
    strcpy(((ERROR_Packet *)packet)->error_message, error_msg);

    packet->size = 2 + 2 + strlen(((ERROR_Packet *) packet)->error_message) + 1;
    packet->size = sizeof(opcode) + sizeof(((ERROR_Packet *) packet)->error_code) + strlen(((ERROR_Packet *) packet)->error_message);

    if(DEBUG) {
        fprintf(DEBUG_STREAM, "\t[DEBUG] Creating ERROR_Packet\tsize: %d\n", packet->size);
        printf("\t\topcode:\t\t%02u\tsize: %d\n", opcode, sizeof(opcode));
        printf("\t\terror_code:\t%02u\tsize: %d\n", error_code, sizeof(error_code));
        printf("\t\terror_msg:\t%s\tsize: %d\n", error_msg, strlen(error_msg));
    }

    free(error_msg);
}

void ERROR_Packet_construct(Packet * packet, unsigned short opcode, unsigned short e_code, char * error_msg)
{
    packet->opcode = opcode;        
    ((ERROR_Packet *)packet)->error_code = e_code;        
    strcpy(((ERROR_Packet *)packet)->error_message, error_msg);

    packet->size = sizeof(opcode) + sizeof(((ERROR_Packet *) packet)->error_code) + strlen(((ERROR_Packet *) packet)->error_message);

    if(DEBUG) {
        fprintf(DEBUG_STREAM, "\t[DEBUG] Creating ERROR_Packet\tsize: %d\n", packet->size);
        printf("\t\topcode:\t\t%02u\tsize: %d\n", opcode, sizeof(opcode));
        printf("\t\terror_code:\t%02u\tsize: %d\n", e_code, sizeof(e_code));
        printf("\t\terror_msg:\t%s\tsize: %d\n", error_msg, strlen(error_msg));
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//================================================================================
//
//  create_packet_from_message
//
//================================================================================
Packet * create_packet_from_message(char * message, int size)
{
    unsigned short opcode = read_message_opcode(message);

    Packet * packet;
    switch(opcode) {
        case 1:
        case 2:
            packet = Packet_init(opcode);
            RWRQ_Packet_construct_msg(packet, opcode, message);
            break;
        case 3:
            packet = Packet_init(opcode);
            DATA_Packet_construct_msg(packet, opcode, message, size - 4);
            break;
        case 4:
            packet = Packet_init(opcode);
            ACK_Packet_construct_msg(packet, opcode, message);
            break;
        case 5:
            packet = Packet_init(opcode);
            ERROR_Packet_construct_msg(packet, opcode, message);
            break;
        default:
            printf("opcode error: opcode = %d\n", opcode);
            exit(1);
            break;
    }

    return packet;

}


//================================================================================
//
//  read_message_opcode
//
//================================================================================
unsigned short read_message_opcode(char * message)
{
    unsigned short opcode;

    opcode = *((unsigned short *) &message[0]);
    opcode = ntohs(opcode);

    if(DEBUG) fprintf(DEBUG_STREAM, "\t[DEBUG] read_message_opcode()\topcode: %02u\n", opcode);

    return opcode;
}

//================================================================================
//
//  read_message_block_num
//
//================================================================================
unsigned short read_message_block_num(char * message)
{
    unsigned short block_num;

    block_num = *((unsigned short *) &message[2]);
    block_num = ntohs(block_num);
    if(DEBUG) fprintf(DEBUG_STREAM, "\t[DEBUG] read_message_block_num()\tblock_num: %02u\n", block_num);

    return block_num;
}

//================================================================================
//
//  read_message_error_code
//
//================================================================================
unsigned short read_message_error_code(char * message)
{
    unsigned short error_code;
    error_code = read_message_block_num(message);
    if(DEBUG) fprintf(DEBUG_STREAM, "\t[DEBUG] read_message_error_code()\terror_code: %02u\n", error_code);
    return error_code;
}

//================================================================================
//
//  read_message_filename
//
//================================================================================
char * read_message_filename(char * message)
{
    // TODO: Add free for this malloc
    char * filename = malloc(FILENAME_LENGTH + 1);
    
    strcpy(filename, message + 2);

    if(DEBUG) fprintf(DEBUG_STREAM, "\t[DEBUG] read_message_filename\tfilename: %s\n", filename);

    return filename;

}

//================================================================================
//
//  read_message_mode
//
//================================================================================
char * read_message_mode(char * message, int filename_size)
{
    // TODO: Add free for this malloc
    char * mode = malloc(FILENAME_LENGTH + 1);
    
    int offset; 
    offset = filename_size + 2 + 1;
    strcpy(mode, message + offset);

    
    if(DEBUG) fprintf(DEBUG_STREAM, "\t[DEBUG] read_message_mode\tmode: %s\n", mode);

    return mode;
}

//================================================================================
//
//  read_message_data
//
//================================================================================
char * read_message_data(char * message, int data_size)
{
    // TODO: Add free for this malloc
    char * data = malloc(data_size + 1);

    if(!data_size) {
        data[0] = 0;
    }
    else {
        memcpy(data, message + DATA_OFFSET, data_size);
    }

    if(DEBUG) {
        fprintf(DEBUG_STREAM, "\t[DEBUG] read_message_data\n");
        printf("\t\toffset: %d\n", DATA_OFFSET);
        printf("\t\tdata: \n%s\n", data);
    }

    return data;
}

//================================================================================
//
//  read_message_error_msg
//
//================================================================================
char * read_message_error_msg(char * message)
{
    // TODO: Add free for this malloc
    char * error_msg = malloc(ERROR_LENGTH + 1);
    
    int offset; 
    offset = strlen(message + 2) + 2 + 1;
    strcpy(error_msg, message + DATA_OFFSET);

    // TODO change something here
    if(DEBUG) fprintf(DEBUG_STREAM, "\t[DEBUG] read_message_error_msg\terror_msg: %s\n", error_msg);

    return error_msg;
}

//================================================================================
//
//  file_open
//
//================================================================================
File_Container * file_open(char * filename, char op)
{
    if(DEBUG) fprintf(DEBUG_STREAM, "\t[DEBUG] opening file: %s\top: %c\n", filename, op);

    File_Container * new_file = malloc(sizeof(File_Container));
    memset(new_file, 0, sizeof(File_Container));

    new_file->fp = fopen(filename, &op);
    memcpy(new_file->filename, filename, strlen(filename) + 1);
    new_file->count = 0; 

    if(new_file->fp == NULL) {
        printf("Failed to open file %s\n", filename);
        exit(1);
    }
    
    return new_file;
}

//================================================================================
//
//  file_close
//
//================================================================================
void file_close(File_Container * this_file)
{
    if(DEBUG) fprintf(DEBUG_STREAM, "\t[DEBUG] closing file: %s\n", this_file->filename);

    fclose(this_file->fp);
    free(this_file);
}

//================================================================================
//
//  file_read_next
//
//================================================================================
int file_read_next(File_Container * this_file, int read_len)
{
    int bytes;
    memset(this_file->current_data, 0, sizeof(this_file->current_data));
    
    bytes = fread(this_file->current_data, sizeof(char), read_len, this_file->fp);
    if(DEBUG) fprintf(DEBUG_STREAM, "\t[DEBUG] file_read_next()\tbytes read: %d\n", bytes);
    return bytes;
}

//================================================================================
//
//  file_write_next
//
//================================================================================
int file_write_next(File_Container * this_file, int write_len)
{
    int bytes;
    bytes = fwrite(this_file->current_data, sizeof(char), write_len, this_file->fp);
    this_file->current_size = bytes;

    if(DEBUG) fprintf(DEBUG_STREAM, "\t[DEBUG] file_write_next()\tbytes written: %d\n", bytes);
    return bytes;
}

//================================================================================
//
//  file_get_size
//
//================================================================================
int file_get_size(File_Container * this_file)
{
    int current, size;

    current = ftell(this_file->fp);
    fseek(this_file->fp, 0, SEEK_END);
    size = ftell(this_file->fp);

    fseek(this_file->fp, current, SEEK_SET);

    return size;
}

//================================================================================
//
//  file_bytes_remaining
//
//================================================================================
int file_bytes_remaining(File_Container * this_file)
{
    int current, size;

    current = ftell(this_file->fp);
    size = file_get_size(this_file);

    return size - current;
}

//================================================================================
//
//  setup_socket
//
//================================================================================
int setup_socket(char * address, int port)
{
    int sock_fd, bind_result;
    struct sockaddr_in addr;

    // Create local socket
    if((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("can't open datagram socket\n");
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    if(address == 0) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else {
        addr.sin_addr.s_addr = inet_addr(address);
    }
    addr.sin_port        = htons(port);

    if(bind(sock_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        printf("can't bind local address\n");
        exit(2);
    }

    return sock_fd;
}

//================================================================================
//
//  send_packet
//
//================================================================================
int send_packet(Packet * packet, int sock_fd, struct sockaddr * serv_addr)
{
    char string[STRING_BUFFER];
    int bytes = 0;
    printf("sending:\t%s\n", Packet_display_string(packet, (char *) &string));

    bytes = sendto(sock_fd, packet->message, packet->size, 0, serv_addr, sizeof(*serv_addr));

    if(DEBUG) fprintf(DEBUG_STREAM, "\t[DEBUG] send_packet()\tbytes sent: %d\n", bytes);

    if(bytes != packet->size) {
        printf("sendto error: %s\n", strerror(errno));
        exit(4);
    }

    return bytes;
}

//================================================================================
//
//  process_message 
//
//================================================================================
void process_message(char * message, int bytes_received, int sock_fd, struct sockaddr * addr)
{
    int num_bytes;
    int data_size;
    char string[STRING_BUFFER];

    Packet * packet;
    Packet * response_packet;

    extern int current_state;
    extern int current_block;
    extern File_Container * transfer_file;

    // Create packet structure from message 
    packet = create_packet_from_message(message, bytes_received);

    if(DEBUG) fprintf(DEBUG_STREAM, "\t[DEBUG] process_message()\tbytes received: %d\n", bytes_received);

    printf("receiving:\t%s\n", Packet_display_string(packet, (char *) &string));

    switch(packet->opcode) {
        case 1: // RRQ
            
            // Check for ready state
            if(current_state != STATE_READY) {
                printf("not able to begin new request\n");
                break;
            }

            // Open file for reading
            transfer_file = file_open(((RWRQ_Packet *)packet)->filename, 'r');
            current_block = 0;

            // Read first block from file
            num_bytes = file_read_next(transfer_file, DATA_SIZE); 

            // Send first packet of DATA
            response_packet = Packet_init(OP_DATA);
            DATA_Packet_construct(response_packet, OP_DATA, ++current_block, transfer_file->current_data, num_bytes);
            Packet_set_message(response_packet);
            send_packet(response_packet, sock_fd, addr);

            current_state = STATE_WAITING_ACK;
            
            break;
        case 2: // WRQ

            // Check for ready state
            if(current_state != STATE_READY) {
                printf("not able to begin new request\n");
                break;
            }

            transfer_file = file_open(((RWRQ_Packet *)packet)->filename, 'a');
            current_block = 0;

            // Send ACK for this packet
            response_packet = Packet_init(OP_ACK);
            ACK_Packet_construct(response_packet, OP_ACK, current_block);
            Packet_set_message(response_packet);
            send_packet(response_packet, sock_fd, addr);

            current_state = STATE_WAITING_DATA;

            break;

        case 3: // DATA

            data_size = bytes_received - DATA_OFFSET;

            current_block = ((DATA_Packet *) packet)->block_num;
            memcpy(transfer_file->current_data, ((DATA_Packet *)packet)->data, data_size);

            num_bytes = file_write_next(transfer_file, data_size);

            // Send ACK for this packet
            response_packet = Packet_init(OP_ACK);
            ACK_Packet_construct(response_packet, OP_ACK, current_block);
            Packet_set_message(response_packet);
            send_packet(response_packet, sock_fd, addr);

            // If last packet, close file, set state
            if(data_size < DATA_SIZE) {
                current_state = STATE_COMPLETE;
                printf("file complete\n\n");
                file_close(transfer_file);
            }
            else {
                current_state = STATE_WAITING_ACK;
            }

            break;

        case 4: // ACK

            // Check that ACK was for the last block sent
            if((((ACK_Packet *) packet)->block_num == 0) && (current_block != ((ACK_Packet *) packet)->block_num)) {
                break;
            }

            if(current_state == STATE_WAITING_LAST) {
                if(file_bytes_remaining(transfer_file) != 0) {
                    printf("error: last_packet_sent flag set but bytes remain in file\n");
                }

                current_state = STATE_COMPLETE;
                printf("file complete\n\n");

                break;
            }

            // Check if file is done
            if(file_bytes_remaining(transfer_file) <= 0) {
                // send empty final packet
                num_bytes = 0;
                memset(transfer_file->current_data, 0, DATA_SIZE);    
            }
            else {
                // Send next packet of DATA
                num_bytes = file_read_next(transfer_file, DATA_SIZE); 
            }

            // Send next packet
            response_packet = Packet_init(OP_DATA);
            DATA_Packet_construct(response_packet, OP_DATA, ++current_block, transfer_file->current_data, num_bytes);
            Packet_set_message(response_packet);
            send_packet(response_packet, sock_fd, addr);

            if(num_bytes < DATA_SIZE) {
                current_state = STATE_WAITING_LAST;
            }
            else {
                current_state = STATE_WAITING_ACK;
            }

            break;

        case 5: // ERROR
            break;

        default:
            break;
    }

    free(packet);
    packet = NULL;

    free(response_packet);
    response_packet = NULL;
}

