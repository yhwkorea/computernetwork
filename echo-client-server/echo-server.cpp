#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <vector>
#include <mutex>
#include <algorithm>

void myerror(const char* msg) {
    fprintf(stderr, "%s %s\n", msg, strerror(errno));
}

struct Param {
    bool echo{false};
    bool broadcast{false};
    uint16_t port{0};

    bool parse(int argc, char* argv[]) {
        for (int i = 1; i < argc;) {
            if (strcmp(argv[i], "-e") == 0) {
                echo = true;
                i++;
                continue;
            }
            if (strcmp(argv[i], "-b") == 0) {
                broadcast = true;
                i++;
                continue;
            }
            port = atoi(argv[i++]);
        }
        return port != 0;
    }
} param;

std::vector<int> clients;
std::mutex mtx;

void recvThread(int sd) {
    {
        std::lock_guard<std::mutex> lock(mtx);
        clients.push_back(sd);
    }

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

        if (param.echo) {
            std::lock_guard<std::mutex> lock(mtx);
            if (param.broadcast) {
                for (int c : clients) {
                    send(c, buf, res, 0); // 모든 클라이언트에게 전송
                }
            } else {
                send(sd, buf, res, 0); // 자신에게만 전송
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(mtx);
        clients.erase(std::remove(clients.begin(), clients.end(), sd), clients.end());
    }
    close(sd);
    printf("disconnected\n");
}

int main(int argc, char* argv[]) {
    if (!param.parse(argc, argv)) {
        printf("syntax: echo-server <port> [-e [-b]]\n");
        return -1;
    }

    int sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd == -1) {
        myerror("socket");
        return -1;
    }

    int opt = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(param.port);

    if (bind(sd, (sockaddr*)&addr, sizeof(addr)) == -1) {
        myerror("bind");
        return -1;
    }

    if (listen(sd, 5) == -1) {
        myerror("listen");
        return -1;
    }

    while (true) {
        sockaddr_in clientAddr;
        socklen_t len = sizeof(clientAddr);
        int csd = accept(sd, (sockaddr*)&clientAddr, &len);
        if (csd == -1) {
            myerror("accept");
            continue;
        }
        std::thread(recvThread, csd).detach();
    }

    close(sd);
}
