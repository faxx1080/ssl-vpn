all: 
	gcc -o tlsclient tlsclient.c -lssl -lcrypto 
	gcc -o tlsserver tlsserver.c -lssl -lcrypto
	gcc -Wall -g3 -O0 -o vpntlsclient vpntlsclient.c -lssl -lcrypto
	gcc -Wall -g3 -O0 -o vpntlsserver vpntlsserver.c -lssl -lcrypto -lcrypt 

clean: 
	rm tlsclient tlsserver 

