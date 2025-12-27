#pragma once
#include <QObject>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>

#include "PacketInfo.h"

struct pcap; // Declaration for libpcap handle type

class CaptureEngine : public QObject {
    Q_OBJECT
public:
    explicit CaptureEngine(QObject* parent = nullptr);
    ~CaptureEngine();

    QStringList listInterfaces(); // List available capture interfaces
    bool start(int ifaceIndex); // Start capture on interface by index
    void stop(); // Stop capture thread and close pcap handle
    bool isRunning() const; // Current running state

    bool setBpfFilter(const QString& filter);  // Set filter

signals:
    void packetCaptured(const PacketInfo& p);  // Emitted when a packet was captured and parsed
    void status(const QString& msg);  // Emitted for status messages
    void filterResult(bool ok, const QString& message); // Emitted when filter apply succeeded/failed

private:
    void captureLoop(const char* device);   // Worker thread function

    std::vector<std::string> devices;   // Cached device names
    std::thread worker;     // Background capture thread
    std::atomic<bool> running{false}; // Atomic running flag to stop the loop safely

    pcap* handle = nullptr;   // Active pcap capture handle
    std::mutex handleMutex;    // Protect handle access

    std::mutex filterMutex; // Protect filter updates
    QString pendingFilter;
};
