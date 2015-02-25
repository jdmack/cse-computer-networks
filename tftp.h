//==============================================================================
//
//          tftp.h
//
//==============================================================================

#define DEBUG 1
#define DEBUG_STREAM stderr

#define SERVER_PORT 60006
#define TIMEOUT     10
#define SERVER_ADDR "127.0.0.1"

#define MESSAGE_SIZE    516
#define DATA_SIZE       512
#define FILENAME_LENGTH 500
#define MODE_LENGTH     8
#define ERROR_LENGTH    512
#define STRING_BUFFER   500

#define OP_RRQ   1
#define OP_WRQ   2
#define OP_DATA  3
#define OP_ACK   4
#define OP_ERROR 5

#define MODE "octet"

#define STATE_READY         700
#define STATE_REQUEST_SENT  701
#define STATE_WAITING_ACK   702
#define STATE_WAITING_DATA  703
#define STATE_COMPLETE      704
#define STATE_WAITING_LAST  705

#define DATA_OFFSET 4
#define ERROR_OFFSET 4


//================================================================================
// Packet
//================================================================================
typedef struct {
    unsigned short opcode;
    int size;
    char message[516];
    
} Packet;

//================================================================================
// RRQ/WRQ Packet
//================================================================================
typedef struct {
    // Parent fields
    unsigned short opcode;
    int size;
    char message[516];

    // RWRQ fields
    char filename[FILENAME_LENGTH];
    char mode[MODE_LENGTH];

} RWRQ_Packet;

//================================================================================
// DATA Packet
//================================================================================
typedef struct {
    // Parent fields
    unsigned short opcode;
    int size;
    char message[516];

    // DATA fields
    unsigned short block_num;
    char data[DATA_SIZE];

} DATA_Packet;

//================================================================================
// ACK Packet
//================================================================================
typedef struct {
    // Parent fields
    unsigned short opcode;
    int size;
    char message[516];

    // ACK fields
    unsigned short block_num;


} ACK_Packet;

//================================================================================
// ERROR Packet
//================================================================================
typedef struct {
    // Parent fields
    unsigned short opcode;
    int size;
    char message[516];

    // ERROR fields
    unsigned short error_code;
    char error_message[ERROR_LENGTH];

} ERROR_Packet;

//================================================================================
// File_Container
//================================================================================
typedef struct {
    FILE * fp;
    char filename[FILENAME_LENGTH];
    int count;
    int current_size;
    char current_data[DATA_SIZE];
} File_Container;

//================================================================================
// Functions
//================================================================================

// Packet
Packet * Packet_init(unsigned short opcode);
char * Packet_display_string(Packet * packet, char * string);
void RWRQ_Packet_construct_msg(Packet * thisP, unsigned short opcode, char * message);
void RWRQ_Packet_construct(Packet * thisP, unsigned short opcode, char * fname, char * mode);
void DATA_Packet_construct_msg(Packet * thisP, unsigned short opcode, char * message, int size);
void DATA_Packet_construct(Packet * thisP, unsigned short opcode, unsigned short b_num, char * data, int size);
void ACK_Packet_construct_msg(Packet * thisP, unsigned short opcode, char * message);
void ACK_Packet_construct(Packet * thisP, unsigned short opcode, unsigned short b_num);
void ERROR_Packet_construct_msg(Packet * thisP, unsigned short opcode, char * message);
void ERROR_Packet_construct(Packet * thisP, unsigned short opcode, unsigned short e_code, char * error_msg);

// Message Parsing
Packet * create_packet_from_message(char * message, int size);
unsigned short read_message_opcode(char * message);
unsigned short read_message_block_num(char * message);
unsigned short read_message_error_code(char * message);
char * read_message_filename(char * message);
char * read_message_mode(char * message, int filename_size);
char * read_message_data(char * message, int size);
char * read_message_error_msg(char * message);

// FILE
File_Container * file_open(char * filename, char op);
int file_read_next(File_Container * this_file, int read_len);
int file_write_next(File_Container * this_file, int write_len);
int file_get_size(File_Container * this_file);

// Socket
int setup_socket(char * address, int port);

// Utility
void write_debug(char * message);

// Server/Client Operation
void process_message(char * message, int bytes_received, int sock_fd, struct sockaddr * addr);

