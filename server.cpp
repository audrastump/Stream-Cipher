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
unsigned char iv[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
};
unsigned char key[32] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
};

int stream_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    //initializing our cipher context and lengths
    EVP_CIPHER_CTX *ctx;
    int length = 0;
    int plaintext_len = 0;
    ctx = EVP_CIPHER_CTX_new();
    //using 256 cbc, our key, and index vector to decrypt
    EVP_DecryptInit_ex(ctx, EVP_chacha20(), nullptr, key, iv);
    //taking the cipher text and its length, decrypting it, and storing it in the plaintext buffer
    //stores length of plaintext in length 
    EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_len);
    
    EVP_DecryptFinal_ex(ctx, plaintext, &length);
    
    EVP_CIPHER_CTX_free(ctx);

    return 0;
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
    if ((bind(server, (struct sockaddr*) &servAddr, sizeof(servAddr))) < 0){
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
    unsigned char inputBuffer[3000];
    unsigned char outputBuffer[3000];
    while(true)
    {
        //clearing our input and output buffers for the next message
        memset(&outputBuffer, 0, sizeof(outputBuffer));
        memset(&inputBuffer, 0, sizeof(inputBuffer));  
        //receiving the encrypted message and printing
        recv(client, clientMessage, sizeof(clientMessage),0);
        printf("Client Encrypted Message: %s\n", clientMessage);
        
        //copying the encrypted message to the input buffer to be decrypted into the output buffer
        memcpy(inputBuffer, clientMessage, strlen(clientMessage));
        

        int finalLength = stream_decrypt(inputBuffer, strlen(clientMessage), key, iv, outputBuffer);

        
        printf("Client Decrypted Message: %s\n",outputBuffer);
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