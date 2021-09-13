OPENSSL_DIR = ./lib/include


LIB = -lcrypto -lssl -ldl -lpthread -lm
INCLUDE = -I/$(OPENSSL_DIR)
LFLAGS = -L/$(OPENSSL_DIR)
DEPS = ./crypto/*.h


CC = gcc
CFLAGS = -Wall -g

all: tls_server tls_client tls_nb_server

tls_nb_server: tls_nb_server.o
	$(CC) -o tls_nb_server tls_nb_server.o $(LFLAGS) $(LIB)

tls_server: tls_server.o
	$(CC) -o tls_server tls_server.o $(LFLAGS) $(LIB)

tls_client: tls_client.o
	$(CC) -o tls_client tls_client.o $(LFLAGS) $(LIB)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $< $(INCLUDE)

clean:
	rm -f tls_server.o tls_client.o tls_server tls_client tls_nb_server tls_nb_server.o
