#OPENSSL_DIR = /home/tuankiet/Documents/openssl-1.1.1g
OPENSSL_DIR = ./lib/include

LIB = -lcrypto -lssl -ldl -lpthread
INCLUDE = -I/$(OPENSSL_DIR)/include
LFLAGS = -L/$(OPENSSL_DIR)
DEPS = rsa.h AEAD.h ECDH.h sha.h ult.h


CC = gcc
CFLAGS = -Wall -g

communication: server client
tls: tls_server tls_client

server: server.c
	$(CC) $(CFLAGS) -o server server.c

client: client.c
	$(CC) $(CFLAGS) -o client client.c

tls_server: tls_server.o
	$(CC) -o tls_server tls_server.o $(LFLAGS) $(LIB)

tls_client: tls_client.o
	$(CC) -o tls_client tls_client.o $(LFLAGS) $(LIB)

demo_handshake: demo_handshake.o
	$(CC) -o demo_handshake demo_handshake.o $(LFLAGS) $(LIB)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $< $(INCLUDE)

clean_demo:
	rm -f demo_handshake demo_handshake.o
clean_socket:
	rm -f server.o client.o server client
clean_tls:
	rm -f tls_server.o tls_client.o tls_server tls_client
clean:
	rm -f server.o client.o tls_server.o tls_client.o server client tls_server tls_client demo_handshake demo_handshake.o