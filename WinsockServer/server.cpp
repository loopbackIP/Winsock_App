#undef  UNICODE

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iostream>

#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

static void InitOpenSSL() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

int main() {
    WSADATA wsaData;
    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo* result = nullptr;
    struct addrinfo hints {};

    const char* certFile = "certs/server.crt";
    const char* keyFile = "certs/server.key";

    // hummmmmm...
    int iSendResult;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    // Initialize Winsock
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed: " << iResult << std::endl;
        return 1;
    }

    // Initialize OpenSSL
    InitOpenSSL();
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "SSL_CTX_new failed." << std::endl;
        WSACleanup();
        return 1;
    }

    if (SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load cert/key." << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    // Setup TCP socket
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    iResult = getaddrinfo(nullptr, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo failed: " << iResult << std::endl;
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for the server to listen for client connections.
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        std::cerr << "socket failed: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    // Set up the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, static_cast<int>(result->ai_addrlen));
    if (iResult == SOCKET_ERROR) {
        std::cerr << "bind failed: " << WSAGetLastError() << std::endl;
        closesocket(ListenSocket);
        freeaddrinfo(result);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "listen failed: " << WSAGetLastError() << std::endl;
        closesocket(ListenSocket);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    std::cout << "TLS Server listening on port " << DEFAULT_PORT << "...\n";

    // Accept a client socket
    ClientSocket = accept(ListenSocket, nullptr, nullptr);
    if (ClientSocket == INVALID_SOCKET) {
        std::cerr << "accept failed: " << WSAGetLastError() << std::endl;
        closesocket(ListenSocket);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    // SSL
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, static_cast<int>(ClientSocket));

    if (SSL_accept(ssl) <= 0) {
        std::cerr << "SSL_accept failed." << std::endl;
        ERR_print_errors_fp(stderr);
    }
    else {
        std::cout << "TLS handshake complete." << "\n";

        char buffer[DEFAULT_BUFLEN] = {};
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes > 0) {
            std::cout << "Received: " << std::string(buffer, bytes) << "\n";
            SSL_write(ssl, buffer, bytes); // Echo back
        }
        else {
            std::cerr << "SSL_read failed." << std::endl;
            ERR_print_errors_fp(stderr);
        }
    }
    
    // cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(ClientSocket);
    closesocket(ListenSocket);
    SSL_CTX_free(ctx);
    WSACleanup();

    return 0;
}