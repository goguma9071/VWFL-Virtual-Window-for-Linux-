#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Function to handle individual client connections
void handle_client(int new_socket) {
    char buffer[1024] = {0};
    
    // Read from socket until EOF or error
    ssize_t bytes_read;
    while ((bytes_read = read(new_socket, buffer, sizeof(buffer))) > 0) {
        printf("Received: %s\n", buffer);
        
        // Process the received data (e.g., parse commands)
        process_debug_command(buffer, new_socket);
        
        memset(buffer, 0, sizeof(buffer));
    }
    
    if (bytes_read == -1) {
        perror("read failed");
    } else if (bytes_read == 0) {
        printf("Client disconnected\n");
    }
    
    close(new_socket);
}

// Main server function
int main() {
    int server_fd;
    
    // Create TCP/IPv4 socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket creation failed");
        exit(1);
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(23946); // Use a specific port for debugging
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind failed");
        close(server_fd);
        exit(1);
    }
    
    printf("Debugger server listening on port 23946\n");
    
    // Listen for incoming connections
    if (listen(server_fd, SOMAXCONN) == -1) {
        perror("listen failed");
        close(server_fd);
        exit(1);
    }
    
    // Accept connections in a loop
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int new_socket = accept(server_fd, 
                               (struct sockaddr *)&client_addr,
                               &addr_len);
        if (new_socket == -1) {
            perror("accept failed");
            continue; // Try next connection
        }
        
        printf("New connection from %s\n",
               inet_ntoa(client_addr.sin_addr));
        
        // Handle the new connection in a separate thread/process
        handle_client(new_socket);
    }
    
    close(server_fd);
}