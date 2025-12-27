#pragma once
#include <QMainWindow>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QTableWidget>
#include <QCheckBox>
#include <QLineEdit>
#include <QTimer>
#include <QMutex>
#include <QVector>
#include <QHash>
#include <QHostInfo>
#include "PpsChart.h"
#include "../core/CaptureEngine.h"

class MainWindow : public QMainWindow {
    Q_OBJECT
public:

    // Main window constructor
    explicit MainWindow(QWidget* parent = nullptr);

private:
    // Convert protocol enum to display string
    QString protoToString(L4Proto p) const;
    // Build BPF filter string from UI controls
    QString buildBpfFilter() const;
    // Apply BPF filter to capture engine
    void applyFilterToEngine();
    // Flush queued packets into table (batch update)
    void flushPendingToTable();

    // DNS resolve helper
    void maybeResolveDnsForCell(int row, int col, const QString& ip);  // Start async DNS resolve for an IP
    void applyDnsResultToCell(int row, int col, const QString& ip, const QString& name); // Update table cell with resolved hostname

    // Stats helpers
    void onStatsTick(); // Called every 1s to update stats and graph
    static QString formatTop(const QHash<QString,int>& map, int topN); // Format top N IP addresses
    static QString formatTopPorts(const QHash<int,int>& map, int topN); // Format top N destination ports


    // Packet capture engine
    CaptureEngine engine;

    // Interface selection and control
    QComboBox* ifaceCombo = nullptr;
    QPushButton* startStopBtn = nullptr;

    // Filter controls
    QCheckBox* tcpCb = nullptr;
    QCheckBox* udpCb = nullptr;
    QCheckBox* icmpCb = nullptr;
    QLineEdit* hostEdit = nullptr;
    QLineEdit* portEdit = nullptr;
    QPushButton* applyBtn = nullptr;

    // Enable/disable DNS resolve
    QCheckBox* dnsCb = nullptr;

    // Stats UI
    QLabel* ppsLbl = nullptr; // Packets per second
    PpsChart* ppsChart = nullptr; // Graph
    QLabel* topSrcLbl = nullptr;  // Top source
    QLabel* topDstLbl = nullptr; // Top destination
    QLabel* topPortsLbl = nullptr; // Top destination

    // Status and packet table
    QLabel* statusLbl = nullptr;
    QTableWidget* table = nullptr;

    // Max rows kept in table
    int maxRows = 2000;

    // batching
    QTimer flushTimer; // Timer for flushing packet
    QMutex pendingMutex;  // Protect pending packet queue
    QVector<PacketInfo> pending;  // Pending packets waiting to be shown

    // DNS cache
    QHash<QString, QString> dnsCache;
    QHash<QString, bool> dnsInFlight;

    // Stats timer
    QTimer statsTimer;
    int packetsThisSecond = 0;
    QHash<QString, int> srcCount;
    QHash<QString, int> dstCount;
    QHash<int, int> dportCount;

    // Export CSV button
    QPushButton* exportCsvBtn = nullptr;
    void exportCsv();  // Export table contents to CSV file


};
