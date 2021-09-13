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



-----------------------------------------------------------
# TLS1.3
Full TLS handshake:

 Client                                           Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*       -------->
                                                  ServerHello  ^ Key
                                                 + key_share*  | Exch
                                            + pre_shared_key*  v
                                        {EncryptedExtensions}  ^  Server
                                        {CertificateRequest*}  v  Params
                                               {Certificate*}  ^
                                         {CertificateVerify*}  | Auth
                                                   {Finished}  v
                               <--------  [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}              -------->
       [Application Data]      <------->  [Application Data]


Ciphersuite
+------------------------------+-------------+
| Description                  | Value       |
+------------------------------+-------------+
| TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
|                              |             |
| TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
|                              |             |
| TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
|                              |             |
| TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
|                              |             |
| TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
+------------------------------+-------------+

Signature schemes:
/* RSASSA-PKCS1-v1_5 algorithms */
rsa_pkcs1_sha256(0x0401),
rsa_pkcs1_sha384(0x0501),
rsa_pkcs1_sha512(0x0601),

/* ECDSA algorithms */
ecdsa_secp256r1_sha256(0x0403),
ecdsa_secp384r1_sha384(0x0503),
ecdsa_secp521r1_sha512(0x0603),

/* RSASSA-PSS algorithms with public key OID rsaEncryption */
rsa_pss_rsae_sha256(0x0804),
rsa_pss_rsae_sha384(0x0805),
rsa_pss_rsae_sha512(0x0806),

/* EdDSA algorithms */
ed25519(0x0807),
ed448(0x0808),

/* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
rsa_pss_pss_sha256(0x0809),
rsa_pss_pss_sha384(0x080a),
rsa_pss_pss_sha512(0x080b),

/* Legacy algorithms */
rsa_pkcs1_sha1(0x0201),
ecdsa_sha1(0x0203),

/* Reserved Code Points */
private_use(0xFE00..0xFFFF),
(0xFFFF)
