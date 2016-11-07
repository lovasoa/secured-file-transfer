# 3Dtrust exercise

Simple secured file transfer implemented in NodeJS.

A secret file (`server/secret.txt`) is located on a server.
A server (launched with `node server/server.js`) can serve this file
to a client, if the client is duly authenticated using a valid certificate.
The server listens on the port 4443 and should be availaible on host `minissl-SERVER`.

A client (launched with `node client/client.js`) can download the file from the server,
after having verified its certificate (mutual authentification).

They use HTTPS as a communication protocol.

The server signs its file using HMAC (SHA256), and sends the signature as an HTTP header.
The client verifies the signature. If it's not correct, then it issues a warning.

The server encrypts its file using AES192 (using `server/aes192-key.bin`), and
a random initialization vector. The client saves the encrypted file and the IV
in two different files.
