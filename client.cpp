#include <stdio.h>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#define MAX_MESSAGE_LENGTH 3000
//CLIENT
int stream_encrypt(unsigned char *plaintext, int plaintext_len, unsigned
char *key, unsigned char *iv, unsigned char *ciphertext)
{
/* Declare cipher context */
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher_type;
    int len, ciphertext_len;
    unsigned char key[32]; 
    unsigned char indexVector[16]; 
    cipher_type = EVP_aes_256_cbc();
    EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher_type, nullptr, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
return ciphertext_len;
}

int main(void)
{
    //VARIABLE DEFINITION
    int PORT = 8080;
    const char *IP = "127.0.0.1";
    char MESSAGE[3000]; 

    //CREATING SOCKET
    sockaddr_in clientSocketAddress;
    memset(&clientSocketAddress, 0, sizeof(clientSocketAddress));
    clientSocketAddress.sin_family = AF_INET;
    clientSocketAddress.sin_addr.s_addr = inet_addr(IP);
    clientSocketAddress.sin_port = htons(PORT);
    int client = socket(AF_INET, SOCK_STREAM, 0);

    //CONNECTING TO SERVER
    if (connect(client,(sockaddr*) &clientSocketAddress, sizeof(clientSocketAddress))>=0){
        printf("Successfully connected to server\n");
    }

    while(true)
    {
        //SENDING MESSAGE TO SERVER
        printf("Client: ");
        std::string input;
        std::getline(std::cin, input);
        unsigned char encrypted_input[3000];
        int ciphertext_len = stream_encrypt(reinterpret_cast<unsigned char*>(input.data()), input.length(), nullptr, nullptr, encrypted_input);
        send(client, encrypted_input, ciphertext_len, 0);
        printf("Waiting for server response\n");

        //RECEIVING MESSAGE FROM SERVER
        memset(&MESSAGE, 0, sizeof(MESSAGE));
        recv(client, (char*)&MESSAGE, sizeof(MESSAGE), 0);
        printf("Server: %s\n", MESSAGE);
        
    }
    close(client);
    printf("Socket closed\n");
    return 0;    
}