#include <stdio.h>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


//SERVER
int PORT = 8080;
int stream_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    /* Declare cipher context */
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    EVP_DecryptFinal_ex(ctx, plaintext+len, &len);
    plaintext_len+=len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int main(void)
{
    //CREATING SOCKET
    int server = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(PORT);
    
    //BINDING SOCKET
    if (bind(server, reinterpret_cast<sockaddr*>(&servAddr), sizeof(servAddr)) <0){
        printf("Uh oh, socket not binding\n");
        return 1;
    }

    //LISTENING FOR CLIENTS
    listen(server,9);
    sockaddr_in clientSockAddr;
    socklen_t clientSockAddrSize = sizeof(clientSockAddr);

    //ACCEPTING CLIENTS
    int client = accept(server, (sockaddr *)&clientSockAddr, &clientSockAddrSize);
    printf("Client connected at port %i\n", PORT);
    char clientMessage[3000];
    while(true)
    {
        memset(clientMessage, 0, sizeof(clientMessage));
        int bytes_received = recv(client, clientMessage, sizeof(clientMessage),0);
        printf("Client: %s\n", clientMessage);
        unsigned char decryptedMessage[3000];

        int plaintext_len = stream_decrypt(reinterpret_cast<unsigned char*>(clientMessage), bytes_received, nullptr, nullptr, decryptedMessage);
        decryptedMessage[plaintext_len] = '\0';
        printf("Decrypted Message: %s\n", decryptedMessage);

        printf("Server: ");

        //SERVER RESPONSE
        std::string input;
        getline(std::cin, input);
        memset(&clientMessage, 0, sizeof(clientMessage));
        strcpy(clientMessage, input.c_str());
        send(client, clientMessage, strlen(clientMessage), 0);
    }
    close(client);
    close(server);
    printf("Socket closed\n");
    return 0;   
}