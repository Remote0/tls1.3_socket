# tls_pseudo

**Source**
- tls_client.c:       client
- tls_server.c:       blocking server
- tls_nb_server.c:    non-blocking server

**Ciphersuite**
1. Cipher:
- aes-128-gcm
- aes-256-gcm
- chacha20-poly1305
2. Hash:
- sha256
- sha384

**Use example**
- Run server (either blocking or non-blocking):
```
./tls_server
./tls_nb_server
```
- Run client:
```
./tls_client -c [Cipher] -h [Hash]
```