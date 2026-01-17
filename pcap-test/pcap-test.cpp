#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct ethernet_hdr {
    u_int8_t ether_dhost[6];  // 목적지 MAC 주소
    u_int8_t ether_shost[6];  // 출발지 MAC 주소
    u_int16_t ether_type;      // 프로토콜 타입 (예: IPv4)
};

struct ipv4_hdr {
    u_int8_t  ip_vhl;          // 버전과 헤더 길이
    u_int8_t  ip_tos;          // 서비스 타입(TOS)
    u_int16_t ip_len;          // 전체 길이 (헤더 + 데이터)
    u_int16_t ip_id;           // 식별자
    u_int16_t ip_off;          // 플래그와 오프셋
    u_int8_t  ip_ttl;          // TTL
    u_int8_t  ip_p;            // 프로토콜 (TCP, UDP 등)
    u_int16_t ip_sum;          // 체크섬
    struct in_addr ip_src, ip_dst; // 출발지 및 목적지 IP 주소
};

// TCP 헤더 구조체 정의
struct tcp_hdr {
    u_int16_t th_sport;        // 출발지 포트
    u_int16_t th_dport;        // 목적지 포트
    u_int32_t th_seq;          // 시퀀스 번호
    u_int32_t th_ack;          // 확인 응답 번호
    u_int8_t  th_offx2;        // 데이터 오프셋
    u_int8_t  th_flags;        // 플래그
    u_int16_t th_win;          // 윈도우 크기
    u_int16_t th_sum;          // 체크섬
    u_int16_t th_urp;          // 긴급 포인터
};

void print_mac_address(u_int8_t *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i < 5) printf(":");
    }
}

void print_ip_address(struct in_addr ip) {
    printf("%s", inet_ntoa(ip));
}

void print_data(const u_char *data, int len) {
    // 데이터 출력 (16진수로 출력)
    if (len == 0){
        printf("-\n");
        return;
    }
    if (len >20)
        len = 20;
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);  // 바이트 출력
        printf("%s", i == len-1 ? "\n" : "|");
    }
}

// 패킷을 읽고 Ethernet 헤더 처리하기
void process_packet(const u_char *packet) {
    struct ethernet_hdr* ethernet_header = (struct ethernet_hdr*)packet;// Ethernet 헤더 구조체에 패킷 내용 읽기
    struct ipv4_hdr* ip_header = (struct ipv4_hdr*)(packet + 14); // Ethernet 헤더를 건너뛰고 IP 헤더 시작
    struct tcp_hdr* tcp_header = (struct tcp_hdr*)(packet + 14 + (ip_header->ip_vhl & 0x0F) * 4);

    if (ntohs(ethernet_header->ether_type) == 0x0800) {  // IPv4
        if (ip_header->ip_p == IPPROTO_TCP) {
            // 목적지 MAC 주소, 출발지 MAC 주소 출력 // Ethernet type (예: IPv4, ARP 등)
            printf("MAC: ");
            print_mac_address(ethernet_header->ether_shost);
            printf(" -> ");
            print_mac_address(ethernet_header->ether_dhost);
            printf(", ");
            //printf("Type: 0x%04x\n", ntohs(ethernet_header->ether_type));

            // 출발지 IP, 목적지 IP 출력
            print_ip_address(ip_header->ip_src);
            printf(":%d", ntohs(tcp_header->th_sport));
            printf(" -> ");
            print_ip_address(ip_header->ip_dst);
            printf(":%d", ntohs(tcp_header->th_dport));
            printf("\n");

            int ip_header_len = (ip_header->ip_vhl & 0x0F) * 4;  // IP 헤더 길이
            int tcp_header_len = (tcp_header->th_offx2 >> 4) * 4;  // TCP 헤더 길이
            int data_offset = 14 + ip_header_len + tcp_header_len;  // 데이터 시작 위치

            const u_char* data = packet + data_offset;  // 데이터 위치
            int data_len = ntohs(ip_header->ip_len) - ip_header_len - tcp_header_len;  // 데이터 크기
            print_data(data, data_len);  // 데이터 출력
            printf("--------------------\n");
        }
    }

}

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);//bytes len 출력
        process_packet(packet);

    }

    pcap_close(pcap);
}
