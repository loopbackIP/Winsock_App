#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

void InitOpenSSL() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

int main() {
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = nullptr;
    struct addrinfo* ptr = nullptr;
    struct addrinfo hints {}; // value initialization

    const char* sendbuf = "this is a test";
    const char* hostname = "127.0.0.1";
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed: " << iResult << std::endl;
        return 1;
    }

    // Initialize OpenSSL
    InitOpenSSL();
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "SSL_CTX_new failed." << std::endl;
        WSACleanup();
        return 1;
    }

    // Setup addrinfo
    ZeroMemory(&hints, sizeof(hints)); // �ּ� ����
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo(hostname, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo failed: " << iResult << std::endl;
        WSACleanup();
        return 1;
    }

    // Try connecting
    for (ptr = result; ptr != nullptr; ptr = ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            /* std::cerr<< "socket failed with error: " << WSAGetLastError() << std::endl;
            WSACleanup();
            return 1;*/
            continue;
        }

        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen));
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        std::cout << "connect failed with error: " << WSAGetLastError() << std::endl;
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, static_cast<int>(ConnectSocket));

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        closesocket(ConnectSocket);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    std::cout << "TLS handshake complete with server." << "\n";

    // Send data
    iResult = SSL_write(ssl, sendbuf, (int)strlen(sendbuf));
    if (iResult <= 0) {
        std::cerr << "SSL_write failed." << std::endl;
        ERR_print_errors_fp(stderr);
    }
    else {
        std::cout << "Sent: " << sendbuf << "\n";
    }

    // Receive response
    iResult = SSL_read(ssl, recvbuf, DEFAULT_BUFLEN);
    if (iResult > 0) {
        std::cout << "Received: " << std::string(recvbuf, iResult) << "\n";
    }
    else {
        std::cerr << "SSL_read failed." << std::endl;
        ERR_print_errors_fp(stderr);
    }

    // cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(ConnectSocket);
    SSL_CTX_free(ctx);
    WSACleanup();

    return 0;
}