#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void print_hex(unsigned char *buf, int len) {
    for(int i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (server_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    unsigned char buffer[4096];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    printf("TCP dump server listening on RAW socket...\n");

    while(1) {
        int bytes_received = recvfrom(server_fd, buffer, sizeof(buffer), 0, 
                                    (struct sockaddr*)&client_addr, &client_len);
        if (bytes_received < 0) {
            perror("Receive failed");
            continue;
        }

        printf("\nReceived %d bytes from %s:\n", bytes_received, 
               inet_ntoa(client_addr.sin_addr));
        print_hex(buffer, bytes_received);
    }

    close(server_fd);
    return 0;
}