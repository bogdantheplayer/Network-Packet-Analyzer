#pragma once
#include <QString>
#include <QDateTime>
#include <QMetaType>

enum class L3Proto { IPv4, IPv6, ARP, OTHER }; // Layer 3 protocol type
enum class L4Proto { TCP, UDP, ICMP, OTHER }; // Layer 4 protocol type

struct PacketInfo {
    QDateTime ts;

    // L3 protocol
    L3Proto l3 = L3Proto::OTHER;
    QString srcIp;
    QString dstIp;

    // L4 protocol
    L4Proto proto = L4Proto::OTHER;
    quint16 srcPort = 0;
    quint16 dstPort = 0;

    int length = 0;  // Total packet length in bytes
    QString info;
};

Q_DECLARE_METATYPE(PacketInfo)
