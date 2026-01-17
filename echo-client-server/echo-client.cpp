#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <iostream>
#include <thread>

void myerror(const char* msg) {
    fprintf(stderr, "%s %s\n", msg, strerror(errno));
}

void usage() {
    printf("syntax : echo-client <ip> <port>\n");
    printf("sample : echo-client 192.168.10.2 1234\n");
}

void recvThread(int sd) {
    printf("connected\n");
    static const int BUFSIZE = 65536;
    char buf[BUFSIZE];
    while (true) {
        ssize_t res = recv(sd, buf, BUFSIZE - 1, 0);
        if (res <= 0) {
            myerror("recv");
            break;
        }
        buf[res] = '\0';
        printf("%s", buf);
        fflush(stdout);
    }
    printf("disconnected\n");
    close(sd);
    exit(0);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    const char* ip = argv[1];
    const char* port = argv[2];

    addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(ip, port, &hints, &res) != 0) {
        myerror("getaddrinfo");
        return -1;
    }

    int sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sd == -1) {
        myerror("socket");
        return -1;
    }

    if (connect(sd, res->ai_addr, res->ai_addrlen) == -1) {
        myerror("connect");
        return -1;
    }

    std::thread(recvThread, sd).detach();

    while (true) {
        std::string line;
        std::getline(std::cin, line);
        line += "\r\n";
        ssize_t res = send(sd, line.c_str(), line.size(), 0);
        if (res <= 0) {
            myerror("send");
            break;
        }
    }
    close(sd);
}
