#include <bits/stdc++.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;
using namespace chrono;

// 검색 모드
enum Mode { LINEAR = 1, BINARY, TRIE };
Mode mode = TRIE;

vector<string> domains;

const int domain_char_size = 10 + 26 + 2;

class Trie {
private:
    vector<Trie*> children;
    bool is_end;

    int char_to_index(char c) {
        if ('0' <= c && c <= '9') return c - '0';
        if ('A' <= c && c <= 'Z') return c - 'A' + 10;
        if ('a' <= c && c <= 'z') return c - 'a' + 10;
        if (c == '.') return 36;
        if (c == '-') return 37;
        return -1;
    }

public:
    Trie() : children(domain_char_size, nullptr), is_end(false) {}
    ~Trie() { for (auto c : children) if (c) delete c; }

    void insert(const string& key) {
        Trie* node = this;
        for (char c : key) {
            int idx = char_to_index(c);
            if (idx == -1) continue;
            if (!node->children[idx]) node->children[idx] = new Trie();
            node = node->children[idx];
        }
        node->is_end = true;
    }

    bool search(const string& key) {
        Trie* node = this;
        for (char c : key) {
            int idx = char_to_index(c);
            if (idx == -1 || !node->children[idx]) return false;
            node = node->children[idx];
        }
        return node->is_end;
    }
};

Trie* root = new Trie();

void usage() {
    printf("syntax : netfilter-test <blocked_list.csv>\n");
    printf("sample : netfilter-test top-1m.csv\n");
}

string extract_host(const unsigned char* payload, int payload_len) {
    string data((char*)payload, payload_len);
    size_t pos = data.find("\r\nHost: ");
    if (pos == string::npos) pos = data.find("Host: ");
    if (pos == string::npos) return "";
    pos += (data[pos] == '\r') ? 8 : 6;
    size_t end = data.find("\r\n", pos);
    return data.substr(pos, end - pos);
}

bool check_blocked(const string& host) {
    auto start = high_resolution_clock::now();
    bool result = false;
    if (mode == LINEAR) {
        for (const string& d : domains) {
            if (d == host) { result = true; break; }
        }
    } else if (mode == BINARY) {
        result = binary_search(domains.begin(), domains.end(), host);
    } else if (mode == TRIE) {
        result = root->search(host);
    }
    auto end = high_resolution_clock::now();
    cout << "[+] Search time: " << duration_cast<nanoseconds>(end - start).count() << " ns\n";
    return result;
}

static u_int32_t get_id(struct nfq_data *tb, unsigned char **data) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    u_int32_t id = 0;
    if (ph) id = ntohl(ph->packet_id);
    nfq_get_payload(tb, data);
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    unsigned char *pkt;
    u_int32_t id = get_id(nfa, &pkt);

    if (pkt) {
        struct iphdr* ip = (struct iphdr*)pkt;
        if (ip->protocol != IPPROTO_TCP) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        int ip_len = ip->ihl * 4;
        struct tcphdr* tcp = (struct tcphdr*)(pkt + ip_len);
        int tcp_len = tcp->doff * 4;
        int total_len = ntohs(ip->tot_len);

        int payload_len = total_len - ip_len - tcp_len;
        if (payload_len <= 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        unsigned char* payload = pkt + ip_len + tcp_len;
        string host = extract_host(payload, payload_len);
        if (!host.empty()) {
            bool blocked = check_blocked(host);
            if (blocked) {
                printf("[!] Blocked host: %s\n", host.c_str());
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    if (argc != 2) { usage(); return 1; }

    printf("Choose mode: 1) linear 2) binary 3) trie : ");
    int m; cin >> m;
    mode = (Mode)m;

    ifstream fin(argv[1]);
    if (!fin) { perror("open failed"); return 1; }

    auto start = high_resolution_clock::now();
    string line;
    while (getline(fin, line)) {
        if (line.empty()) continue;
        size_t comma = line.find(',');
        if (comma == string::npos) continue;
        string domain = line.substr(comma + 1);

        if (mode == TRIE) root->insert(domain);
        else domains.push_back(domain);
    }
    if (mode == BINARY) sort(domains.begin(), domains.end());
    auto end = high_resolution_clock::now();
    cout << "[+] Load time: " << duration_cast<milliseconds>(end - start).count() << " ms\n";

    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open"); return 1; }
    if (nfq_unbind_pf(h, AF_INET) < 0) { perror("unbind_pf"); return 1; }
    if (nfq_bind_pf(h, AF_INET) < 0) { perror("bind_pf"); return 1; }

    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) { perror("create_queue"); return 1; }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) { perror("set_mode"); return 1; }

    int fd = nfq_fd(h);
    char buf[4096] __attribute__ ((aligned));
    while (true) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) nfq_handle_packet(h, buf, rv);
        else if (rv < 0 && errno == ENOBUFS) continue;
        else break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
