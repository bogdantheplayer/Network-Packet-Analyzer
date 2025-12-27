#include "CaptureEngine.h"

#include <pcap.h>
#include <QDateTime>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>


// Link-layer header sizes
static constexpr int ETH_LEN  = 14; // Ethernet header
static constexpr int NULL_LEN = 4;  // Loopback/NULL header

#pragma pack(push, 1)  // Use packed structs to match on-wire packet headers

// Ethernet II header
struct EthHeader {
    quint8  dst[6];
    quint8  src[6];
    quint16 type; // big endian ethertype
};

// 802.1Q VLAN tag header
struct VlanTag {
    quint16 tci;
    quint16 type; // big endian
};

// IPv4 header
struct IPv4Header {
    quint8  ver_ihl;
    quint8  tos;
    quint16 tot_len;
    quint16 id;
    quint16 frag_off;
    quint8  ttl;
    quint8  protocol;
    quint16 checksum;
    quint32 saddr;
    quint32 daddr;
};


// IPv6 header
struct IPv6Header {
    quint32 ver_tc_fl;      // version
    quint16 payload_len;
    quint8  next_header;
    quint8  hop_limit;
    quint8  saddr[16];
    quint8  daddr[16];
};

// Minimal TCP header
struct TCPHeaderMin {
    quint16 srcPort;
    quint16 dstPort;
    quint32 seq;
    quint32 ack;
    quint8  offsetRes;
    quint8  flags;
    quint16 window;
    quint16 checksum;
    quint16 urgPtr;
};

// Minimal ICMP header
struct ICMPHeaderMin {
    quint8 type;
    quint8 code;
    quint16 checksum;
};

// ARP header
struct ARPHeader {
    quint16 htype;
    quint16 ptype;
    quint8  hlen;
    quint8  plen;
    quint16 oper;
    quint8  sha[6];
    quint32 spa;
    quint8  tha[6];
    quint32 tpa;
};
#pragma pack(pop)

// Extract IPv4 header length
static int ipv4HeaderLenBytes(const IPv4Header* ip) {
    return (ip->ver_ihl & 0x0F) * 4;
}

// Convert TCP flags bitmask to readable string
static QString tcpFlagsToString(quint8 f) {
    QStringList fl;
    if (f & 0x02) fl << "SYN";
    if (f & 0x10) fl << "ACK";
    if (f & 0x01) fl << "FIN";
    if (f & 0x04) fl << "RST";
    if (f & 0x08) fl << "PSH";
    if (f & 0x20) fl << "URG";
    if (f & 0x40) fl << "ECE";
    if (f & 0x80) fl << "CWR";
    return fl.join(",");
}

CaptureEngine::CaptureEngine(QObject* parent) : QObject(parent) {}

CaptureEngine::~CaptureEngine() {
    stop();  // Ensure worker thread is stopped and handle is closed
}

QStringList CaptureEngine::listInterfaces() {
    devices.clear();    // Refresh device list
    QStringList list;

    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* alldevs = nullptr;

    // Ask pcap for all capture devices
    if (pcap_findalldevs(&alldevs, errbuf) != 0 || !alldevs) {
        emit status(QString("pcap_findalldevs failed: %1").arg(errbuf));
        return list;
    }

    // Store device names and build readable list for the UI
    int i = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next, ++i) {
        devices.push_back(d->name ? d->name : "");

        QString name = d->description
            ? QString::fromLocal8Bit(d->description)
            : QString::fromLocal8Bit(d->name ? d->name : "unknown");

        list << QString("%1) %2").arg(i).arg(name);
    }

    pcap_freealldevs(alldevs);
    return list;
}

bool CaptureEngine::start(int ifaceIndex) {
    // Validate state and index
    if (running || ifaceIndex < 0 || ifaceIndex >= (int)devices.size())
        return false;

    running = true;
    std::string dev = devices[(size_t)ifaceIndex];

    // Launch capture in a background thread
    worker = std::thread([this, dev]() {
        captureLoop(dev.c_str());
    });

    return true;
}

void CaptureEngine::stop() {
    running = false;    // Signal thread to stop



    // Break pcap loop if it is waiting inside pcap_next_ex
    {
        std::lock_guard<std::mutex> lk(handleMutex);
        if (handle) pcap_breakloop(handle);
    }

    // Join worker thread
    if (worker.joinable())
        worker.join();

    // Close pcap handle safely
    {
        std::lock_guard<std::mutex> lk(handleMutex);
        if (handle) {
            pcap_close(handle);
            handle = nullptr;
        }
    }

    emit status("Stopped.");
}

bool CaptureEngine::isRunning() const {
    return running.load();
}

bool CaptureEngine::setBpfFilter(const QString& filter) {

    // Save filter so it can be applied later at Start
    {
        std::lock_guard<std::mutex> lk(filterMutex);
        pendingFilter = filter;
    }

    // If capture is not running yet, nothing else to do
    std::lock_guard<std::mutex> lk(handleMutex);
    if (!handle) {
        emit filterResult(true, "Filter saved (will apply on Start).");
        return true;
    }

    QString f = filter.trimmed();

    // Clear filter => match all
    if (f.isEmpty()) {
        bpf_program prog{};
        if (pcap_compile(handle, &prog, "true", 1, PCAP_NETMASK_UNKNOWN) < 0) {
            auto msg = QString("Failed to clear filter: %1").arg(pcap_geterr(handle));
            emit filterResult(false, msg);
            return false;
        }

        bool ok = (pcap_setfilter(handle, &prog) == 0);
        pcap_freecode(&prog);

        if (ok) emit filterResult(true, "Filter cleared (showing all packets).");
        else    emit filterResult(false, QString("Failed to clear filter: %1").arg(pcap_geterr(handle)));

        return ok;
    }


    // Compile user filter string
    bpf_program prog{};
    std::string fs = f.toStdString();

    if (pcap_compile(handle, &prog, fs.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
        auto msg = QString("Invalid filter: %1").arg(pcap_geterr(handle));
        emit filterResult(false, msg);
        return false;
    }

    // Apply compiled filter to running capture handle
    if (pcap_setfilter(handle, &prog) < 0) {
        auto msg = QString("Filter apply failed: %1").arg(pcap_geterr(handle));
        pcap_freecode(&prog);
        emit filterResult(false, msg);
        return false;
    }

    pcap_freecode(&prog);
    emit filterResult(true, QString("Filter applied: %1").arg(f));
    return true;
}

void CaptureEngine::captureLoop(const char* device) {
    char errbuf[PCAP_ERRBUF_SIZE]{};

    // Open device in promiscuous mode (1), read timeout 1000ms
    pcap_t* local = pcap_open_live(device, 65535, 1, 1000, errbuf);
    if (!local) {
        emit status(QString("pcap_open_live failed: %1").arg(errbuf));
        running = false;
        return;
    }
    
    // Detect datalink type to know how to parse L2
    int dlt = pcap_datalink(local);
    int l2Offset = 0;

    if (dlt == DLT_EN10MB) {
        l2Offset = 0; // We parse Ethernet ourselves
    } else if (dlt == DLT_NULL) {
        l2Offset = NULL_LEN;  // Loopback / NULL header present
    } else if (dlt == DLT_RAW) {
        l2Offset = 0;   // Raw IP packets
    } else {
        emit status(QString("Unsupported datalink type: %1").arg(dlt));
        pcap_close(local);
        running = false;
        return;
    }


    // Store handle for other methods
    {
        std::lock_guard<std::mutex> lk(handleMutex);
        handle = local;
    }

    emit status(QString("Capturing on: %1 (DLT=%2)").arg(QString::fromLocal8Bit(device)).arg(dlt));

    // Apply pending filter when capture starts
    {
        QString f;
        {
            std::lock_guard<std::mutex> lk(filterMutex);
            f = pendingFilter.trimmed();
        }
        if (!f.isEmpty()) {
            bpf_program prog{};
            std::string fs = f.toStdString();
            if (pcap_compile(local, &prog, fs.c_str(), 1, PCAP_NETMASK_UNKNOWN) == 0 &&
                pcap_setfilter(local, &prog) == 0) {
                emit filterResult(true, QString("Filter applied: %1").arg(f));
            } else {
                emit filterResult(false, QString("Filter apply failed: %1").arg(pcap_geterr(local)));
            }
            pcap_freecode(&prog);
        }
    }

    // UI throttle to limit how many packets per second are sent to UI
    int emittedThisSecond = 0;
    auto lastSec = std::chrono::steady_clock::now();

    while (running) {
        pcap_pkthdr* hdr = nullptr;
        const u_char* data = nullptr;

        // Read next packet
        int r = pcap_next_ex(local, &hdr, &data);
        if (r == 0) continue;  // timeout
        if (r < 0) break;  // error or EOF
        if (!hdr || !data) continue;

        // Reset throttle every second
        auto now = std::chrono::steady_clock::now();
        if (now - lastSec >= std::chrono::seconds(1)) {
            emittedThisSecond = 0;
            lastSec = now;
        }
        if (emittedThisSecond++ > 300) continue;

        PacketInfo p;
        p.ts = QDateTime::currentDateTime();
        p.length = (int)hdr->len;

        // DLT_NULL / RAW
        if (dlt == DLT_RAW) {
            // Raw IP
            // IPv4
            if (hdr->caplen < 1) continue;
            quint8 ver = (data[0] >> 4) & 0x0F;

            if (ver == 4) {
                if (hdr->caplen < sizeof(IPv4Header)) continue;
                const auto* ip = reinterpret_cast<const IPv4Header*>(data);
                // Validate IHL
                int ihl = ipv4HeaderLenBytes(ip);
                if (ihl < 20 || ihl > 60) continue;
                if (hdr->caplen < (unsigned)ihl) continue;

                p.l3 = L3Proto::IPv4;

                // Convert IPv4 addresses to text
                char src[INET_ADDRSTRLEN]{}, dst[INET_ADDRSTRLEN]{};
                inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
                inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));
                p.srcIp = src; p.dstIp = dst;

                // L4 starts after IPv4 header
                const u_char* l4 = data + ihl;

                // Detect transport protocol
                if (ip->protocol == 6) p.proto = L4Proto::TCP;
                else if (ip->protocol == 17) p.proto = L4Proto::UDP;
                else if (ip->protocol == 1) p.proto = L4Proto::ICMP;
                else p.proto = L4Proto::OTHER;


                // Parse TCP ports + flags
                if (p.proto == L4Proto::TCP && hdr->caplen >= (unsigned)(ihl + sizeof(TCPHeaderMin))) {
                    const auto* tcp = reinterpret_cast<const TCPHeaderMin*>(l4);
                    p.srcPort = ntohs(tcp->srcPort);
                    p.dstPort = ntohs(tcp->dstPort);
                    p.info = tcpFlagsToString(tcp->flags);

                // Parse UDP ports
                } else if (p.proto == L4Proto::UDP && hdr->caplen >= (unsigned)(ihl + 8)) {
                    p.srcPort = (quint16)((l4[0] << 8) | l4[1]);
                    p.dstPort = (quint16)((l4[2] << 8) | l4[3]);
                    p.info = "UDP";

                // Parse ICMP type/code
                } else if (p.proto == L4Proto::ICMP && hdr->caplen >= (unsigned)(ihl + sizeof(ICMPHeaderMin))) {
                    const auto* icmp = reinterpret_cast<const ICMPHeaderMin*>(l4);
                    p.info = QString("type=%1 code=%2").arg(icmp->type).arg(icmp->code);
                }
                emit packetCaptured(p);


            // IPv6
            } else if (ver == 6) {
                if (hdr->caplen < sizeof(IPv6Header)) continue;
                const auto* ip6 = reinterpret_cast<const IPv6Header*>(data);
                p.l3 = L3Proto::IPv6;

                // Convert IPv6 addresses to text
                char src[INET6_ADDRSTRLEN]{}, dst[INET6_ADDRSTRLEN]{};
                inet_ntop(AF_INET6, ip6->saddr, src, sizeof(src));
                inet_ntop(AF_INET6, ip6->daddr, dst, sizeof(dst));
                p.srcIp = src; p.dstIp = dst;

                // L4 starts after IPv6 header
                const u_char* l4 = data + sizeof(IPv6Header);
                quint8 nh = ip6->next_header;

                // Detect next header
                if (nh == 6) p.proto = L4Proto::TCP;
                else if (nh == 17) p.proto = L4Proto::UDP;
                else if (nh == 58) p.proto = L4Proto::ICMP; // ICMPv6
                else p.proto = L4Proto::OTHER;

                // Parse ports for TCP/UDP
                if ((p.proto == L4Proto::TCP || p.proto == L4Proto::UDP) &&
                    hdr->caplen >= sizeof(IPv6Header) + 4) {
                    p.srcPort = (quint16)((l4[0] << 8) | l4[1]);
                    p.dstPort = (quint16)((l4[2] << 8) | l4[3]);
                    if (p.proto == L4Proto::TCP && hdr->caplen >= sizeof(IPv6Header) + sizeof(TCPHeaderMin)) {
                        const auto* tcp = reinterpret_cast<const TCPHeaderMin*>(l4);
                        p.info = tcpFlagsToString(tcp->flags);
                    } else {
                        p.info = "UDP/IPv6";
                    }

                // Parse ICMPv6
                } else if (p.proto == L4Proto::ICMP && hdr->caplen >= sizeof(IPv6Header) + sizeof(ICMPHeaderMin)) {
                    const auto* icmp = reinterpret_cast<const ICMPHeaderMin*>(l4);
                    p.info = QString("ICMPv6 type=%1 code=%2").arg(icmp->type).arg(icmp->code);
                }

                emit packetCaptured(p);
            }

            continue;
        }

        // DLT_NULL
        if (dlt == DLT_NULL) {
            // Loopback header
            if (hdr->caplen < (unsigned)NULL_LEN + 1) continue;
            const u_char* ipStart = data + NULL_LEN;
            quint8 ver = (ipStart[0] >> 4) & 0x0F;

            // Only handle IPv4 here 
            if (ver == 4) {
                if (hdr->caplen < (unsigned)NULL_LEN + sizeof(IPv4Header)) continue;
                const auto* ip = reinterpret_cast<const IPv4Header*>(ipStart);
                int ihl = ipv4HeaderLenBytes(ip);
                if (ihl < 20 || ihl > 60) continue;
                if (hdr->caplen < (unsigned)(NULL_LEN + ihl)) continue;

                p.l3 = L3Proto::IPv4;

                char src[INET_ADDRSTRLEN]{}, dst[INET_ADDRSTRLEN]{};
                inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
                inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));
                p.srcIp = src; p.dstIp = dst;

                const u_char* l4 = ipStart + ihl;
                if (ip->protocol == 6) p.proto = L4Proto::TCP;
                else if (ip->protocol == 17) p.proto = L4Proto::UDP;
                else if (ip->protocol == 1) p.proto = L4Proto::ICMP;
                else p.proto = L4Proto::OTHER;

                if (p.proto == L4Proto::TCP && hdr->caplen >= (unsigned)(NULL_LEN + ihl + sizeof(TCPHeaderMin))) {
                    const auto* tcp = reinterpret_cast<const TCPHeaderMin*>(l4);
                    p.srcPort = ntohs(tcp->srcPort);
                    p.dstPort = ntohs(tcp->dstPort);
                    p.info = tcpFlagsToString(tcp->flags);
                } else if (p.proto == L4Proto::UDP && hdr->caplen >= (unsigned)(NULL_LEN + ihl + 8)) {
                    p.srcPort = (quint16)((l4[0] << 8) | l4[1]);
                    p.dstPort = (quint16)((l4[2] << 8) | l4[3]);
                    p.info = "UDP";
                } else if (p.proto == L4Proto::ICMP && hdr->caplen >= (unsigned)(NULL_LEN + ihl + sizeof(ICMPHeaderMin))) {
                    const auto* icmp = reinterpret_cast<const ICMPHeaderMin*>(l4);
                    p.info = QString("type=%1 code=%2").arg(icmp->type).arg(icmp->code);
                }

                emit packetCaptured(p);
            }
            continue;
        }

        // DLT_EN10MB
        if (hdr->caplen < (unsigned)(l2Offset + sizeof(EthHeader))) continue;

        const u_char* ptr = data + l2Offset;
        auto* eth = (const EthHeader*)ptr;

        // Ethertype indicates payload type
        quint16 etherType = ntohs(eth->type);
        ptr += sizeof(EthHeader);

        // Handle 802.1Q VLAN tag
        if (etherType == 0x8100) {
            if (hdr->caplen < (unsigned)(l2Offset + sizeof(EthHeader) + sizeof(VlanTag))) continue;
            auto* vlan = (const VlanTag*)ptr;
            etherType = ntohs(vlan->type);
            ptr += sizeof(VlanTag);
        }

        // ARP
        if (etherType == 0x0806) {
            if (hdr->caplen < (unsigned)(ptr - data + sizeof(ARPHeader))) continue;
            auto* arp = (const ARPHeader*)ptr;

            p.l3 = L3Proto::ARP;

            // Convert ARP IPv4 addresses to text
            char spa[INET_ADDRSTRLEN]{}, tpa[INET_ADDRSTRLEN]{};
            inet_ntop(AF_INET, &arp->spa, spa, sizeof(spa));
            inet_ntop(AF_INET, &arp->tpa, tpa, sizeof(tpa));
            p.srcIp = spa;
            p.dstIp = tpa;
            
            // Decode ARP operation
            quint16 op = ntohs(arp->oper);
            if (op == 1) p.info = QString("ARP who-has %1? tell %2").arg(p.dstIp, p.srcIp);
            else if (op == 2) p.info = QString("ARP is-at %1").arg(p.srcIp);
            else p.info = QString("ARP op=%1").arg(op);

            emit packetCaptured(p);
            continue;
        }

        // IPv4
        if (etherType == 0x0800) {
            if (hdr->caplen < (unsigned)(ptr - data + sizeof(IPv4Header))) continue;
            auto* ip = (const IPv4Header*)ptr;

            // Validate version
            if (((ip->ver_ihl >> 4) & 0x0F) != 4) continue;

            // Validate header length
            int ihl = ipv4HeaderLenBytes(ip);
            if (ihl < 20 || ihl > 60) continue;
            if (hdr->caplen < (unsigned)(ptr - data + ihl)) continue;

            p.l3 = L3Proto::IPv4;

            char src[INET_ADDRSTRLEN]{}, dst[INET_ADDRSTRLEN]{};
            inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
            inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));
            p.srcIp = src; p.dstIp = dst;

            const u_char* l4 = ptr + ihl;

            if (ip->protocol == 6) p.proto = L4Proto::TCP;
            else if (ip->protocol == 17) p.proto = L4Proto::UDP;
            else if (ip->protocol == 1) p.proto = L4Proto::ICMP;
            else p.proto = L4Proto::OTHER;

            if (p.proto == L4Proto::TCP && hdr->caplen >= (unsigned)(l4 - data + sizeof(TCPHeaderMin))) {
                const auto* tcp = reinterpret_cast<const TCPHeaderMin*>(l4);
                p.srcPort = ntohs(tcp->srcPort);
                p.dstPort = ntohs(tcp->dstPort);
                p.info = tcpFlagsToString(tcp->flags);
            } else if (p.proto == L4Proto::UDP && hdr->caplen >= (unsigned)(l4 - data + 8)) {
                p.srcPort = (quint16)((l4[0] << 8) | l4[1]);
                p.dstPort = (quint16)((l4[2] << 8) | l4[3]);
                p.info = "UDP";
            } else if (p.proto == L4Proto::ICMP && hdr->caplen >= (unsigned)(l4 - data + sizeof(ICMPHeaderMin))) {
                const auto* icmp = reinterpret_cast<const ICMPHeaderMin*>(l4);
                p.info = QString("type=%1 code=%2").arg(icmp->type).arg(icmp->code);
            }

            emit packetCaptured(p);
            continue;
        }

        // IPv6
        if (etherType == 0x86DD) {
            if (hdr->caplen < (unsigned)(ptr - data + sizeof(IPv6Header))) continue;
            auto* ip6 = (const IPv6Header*)ptr;
            p.l3 = L3Proto::IPv6;

            char src[INET6_ADDRSTRLEN]{}, dst[INET6_ADDRSTRLEN]{};
            inet_ntop(AF_INET6, ip6->saddr, src, sizeof(src));
            inet_ntop(AF_INET6, ip6->daddr, dst, sizeof(dst));
            p.srcIp = src; p.dstIp = dst;

            const u_char* l4 = ptr + sizeof(IPv6Header);
            quint8 nh = ip6->next_header;

            if (nh == 6) p.proto = L4Proto::TCP;
            else if (nh == 17) p.proto = L4Proto::UDP;
            else if (nh == 58) p.proto = L4Proto::ICMP; // ICMPv6
            else p.proto = L4Proto::OTHER;

            if ((p.proto == L4Proto::TCP || p.proto == L4Proto::UDP) &&
                hdr->caplen >= (unsigned)(l4 - data + 4)) {
                p.srcPort = (quint16)((l4[0] << 8) | l4[1]);
                p.dstPort = (quint16)((l4[2] << 8) | l4[3]);

                if (p.proto == L4Proto::TCP && hdr->caplen >= (unsigned)(l4 - data + sizeof(TCPHeaderMin))) {
                    const auto* tcp = reinterpret_cast<const TCPHeaderMin*>(l4);
                    p.info = tcpFlagsToString(tcp->flags);
                } else {
                    p.info = "UDP/IPv6";
                }
            } else if (p.proto == L4Proto::ICMP && hdr->caplen >= (unsigned)(l4 - data + sizeof(ICMPHeaderMin))) {
                const auto* icmp = reinterpret_cast<const ICMPHeaderMin*>(l4);
                p.info = QString("ICMPv6 type=%1 code=%2").arg(icmp->type).arg(icmp->code);
            }

            emit packetCaptured(p);
            continue;
        }

        // Other ethertypes -> ignore
    }

    emit status("Capture thread ended.");
}
