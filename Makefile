RM := rm -f

targets := server_test test_echo_client tftpserver tftpclient CLIENT/tftpclient SERVER/tftpserver CLIENT/foo.txt SERVER/bar.txt

all:
	$(RM) $(targets)
	gcc -g -o tftpserver tftpserver.c tftp.c
	gcc -g -o tftpclient tftpclient.c tftp.c
	cp tftpserver SERVER/
	cp tftpclient CLIENT/

test:
	gcc test_echo_client.c -o test_echo_client
	gcc server_test.c -o server_test

clean:
	$(RM) $(targets)

