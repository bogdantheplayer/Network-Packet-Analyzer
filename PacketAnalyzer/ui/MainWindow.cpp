#include "MainWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <algorithm>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QMessageBox>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {

    // Main container widget
    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);

    // Top row
    auto* top = new QHBoxLayout();
    ifaceCombo = new QComboBox(this);  // Interface dropdown
    startStopBtn = new QPushButton("Start", this);  // Start/Stop capture button
    exportCsvBtn = new QPushButton("Export CSV", this);  // Export current table to CSV

    top->addWidget(new QLabel("Interface:", this));
    top->addWidget(ifaceCombo, 1);
    top->addWidget(exportCsvBtn);
    top->addWidget(startStopBtn);

    // Filter row
    auto* filters = new QHBoxLayout();
    // Protocol filters
    tcpCb = new QCheckBox("TCP", this);
    udpCb = new QCheckBox("UDP", this);
    icmpCb = new QCheckBox("ICMP", this);

    // Host/IP filter input
    hostEdit = new QLineEdit(this);
    hostEdit->setPlaceholderText("Host/IP (ex: 8.8.8.8)");
    
    // Port filter input
    portEdit = new QLineEdit(this);
    portEdit->setPlaceholderText("Port (ex: 443)");
    portEdit->setMaximumWidth(120);
    
    // Apply filter to pcap
    applyBtn = new QPushButton("Apply Filter", this);
    dnsCb = new QCheckBox("Resolve DNS", this); // Reverse DNS resolve for IPs shown in table

    filters->addWidget(new QLabel("Filters:", this));
    filters->addWidget(tcpCb);
    filters->addWidget(udpCb);
    filters->addWidget(icmpCb);
    filters->addSpacing(12);
    filters->addWidget(hostEdit, 1);
    filters->addWidget(portEdit);
    filters->addWidget(applyBtn);
    filters->addSpacing(12);
    filters->addWidget(dnsCb);

    // Stats row
    auto* stats = new QHBoxLayout();
    ppsLbl = new QLabel("PPS: 0", this);  // Packets per second label
    ppsLbl->setMinimumWidth(120);

    ppsChart = new PpsChart(this);    // Graph
    ppsChart->setCapacity(60);


    // Top lists
    topSrcLbl = new QLabel("Top SRC:\n-", this);
    topDstLbl = new QLabel("Top DST:\n-", this);
    topPortsLbl = new QLabel("Top DPorts:\n-", this);

    topSrcLbl->setMinimumWidth(260);
    topDstLbl->setMinimumWidth(260);
    topPortsLbl->setMinimumWidth(220);

    stats->addWidget(ppsLbl);
    stats->addWidget(ppsChart);
    stats->addSpacing(12);
    stats->addWidget(topSrcLbl);
    stats->addSpacing(12);
    stats->addWidget(topDstLbl);
    stats->addSpacing(12);
    stats->addWidget(topPortsLbl);
    stats->addStretch(1);

    // Table
    table = new QTableWidget(this);
    table->setColumnCount(8);
    table->setHorizontalHeaderLabels({"Time","Source IP","Destination IP","Protocol","SourcePort","DestinationPort","Length","Information"});
    table->horizontalHeader()->setStretchLastSection(true);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSortingEnabled(false);

    statusLbl = new QLabel("Ready.", this);

    root->addLayout(top);
    root->addLayout(filters);
    root->addLayout(stats);
    root->addWidget(table, 1);
    root->addWidget(statusLbl);

    setCentralWidget(central);
    resize(1300, 700);
    setWindowTitle("Network Packet Analyzer");

    // Populate interfaces
    ifaceCombo->addItems(engine.listInterfaces());

    // Status messages
    connect(&engine, &CaptureEngine::status, this, [this](const QString& s){
        statusLbl->setText(s);
        statusLbl->setStyleSheet("");
    }, Qt::QueuedConnection);

    // Filter feedback (green or red)
    connect(&engine, &CaptureEngine::filterResult, this,
            [this](bool ok, const QString& msg) {
                statusLbl->setText(msg);
                statusLbl->setStyleSheet(ok
                    ? "QLabel { color: #1a7f37; font-weight: 600; }"
                    : "QLabel { color: #d1242f; font-weight: 600; }");

                if (ok) {
                    table->setRowCount(0);
                    if (ppsChart) ppsChart->clear();
                }
            }, Qt::QueuedConnection);


    // Receive captured packets from engine
    // Packets are push into a queue and flush in batches
    connect(&engine, &CaptureEngine::packetCaptured, this,
            [this](const PacketInfo& p) {
                QMutexLocker lk(&pendingMutex);
                pending.push_back(p);
            }, Qt::QueuedConnection);

    // Flush pending packets to table every 50ms
    flushTimer.setInterval(50);
    connect(&flushTimer, &QTimer::timeout, this, [this]() { flushPendingToTable(); });
    flushTimer.start();

     // Update every 1 second
    statsTimer.setInterval(1000);
    connect(&statsTimer, &QTimer::timeout, this, [this]() { onStatsTick(); });
    statsTimer.start();

    // Start/Stop
    connect(startStopBtn, &QPushButton::clicked, this, [this]() {
        if (!engine.isRunning()) {
             // Clear pending queue and UI table
            { QMutexLocker lk(&pendingMutex); pending.clear(); }
            table->setRowCount(0);

            // reset stats
            packetsThisSecond = 0;
            srcCount.clear();
            dstCount.clear();
            dportCount.clear();
            ppsLbl->setText("PPS: 0");
            topSrcLbl->setText("Top SRC:\n-");
            topDstLbl->setText("Top DST:\n-");
            topPortsLbl->setText("Top DPorts:\n-");
            if (ppsChart) ppsChart->clear();


            // Start capture on selected interface
            engine.start(ifaceCombo->currentIndex());
            startStopBtn->setText("Stop");
            applyFilterToEngine();   // Apply current filter
        } else {
            engine.stop();  // Stop capture
            startStopBtn->setText("Start");
        }
    });

    // Apply Filter
    connect(applyBtn, &QPushButton::clicked, this, [this]() {
        applyFilterToEngine();
    });

    // Export CSV
    connect(exportCsvBtn, &QPushButton::clicked, this, &MainWindow::exportCsv);
}

void MainWindow::flushPendingToTable() {

    // Move pending packets into local batch
    QVector<PacketInfo> batch;
    {
        QMutexLocker lk(&pendingMutex);
        if (pending.isEmpty()) return;
        batch = std::move(pending);
        pending.clear();
    }

    const int maxPerTick = 200;  // Limit UI work per tick to avoid freezes on heavy traffic
    if (batch.size() > maxPerTick) batch.resize(maxPerTick);

    table->setUpdatesEnabled(false);    // Disable updates while inserting rows

    for (const auto& p : batch) {

        // Update rolling counters 
        packetsThisSecond++;
        if (!p.srcIp.isEmpty()) srcCount[p.srcIp] += 1;
        if (!p.dstIp.isEmpty()) dstCount[p.dstIp] += 1;
        if (p.dstPort > 0) dportCount[(int)p.dstPort] += 1;


        // Insert row in table
        int row = table->rowCount();
        table->insertRow(row);

        table->setItem(row, 0, new QTableWidgetItem(p.ts.toString("HH:mm:ss.zzz")));
        table->setItem(row, 1, new QTableWidgetItem(p.srcIp));
        table->setItem(row, 2, new QTableWidgetItem(p.dstIp));
        table->setItem(row, 3, new QTableWidgetItem(protoToString(p.proto)));
        table->setItem(row, 4, new QTableWidgetItem(QString::number(p.srcPort)));
        table->setItem(row, 5, new QTableWidgetItem(QString::number(p.dstPort)));
        table->setItem(row, 6, new QTableWidgetItem(QString::number(p.length)));
        table->setItem(row, 7, new QTableWidgetItem(p.info));

        if (table->rowCount() > maxRows) table->removeRow(0);  // Remove oldest row



        // Reverse DNS
        if (dnsCb->isChecked()) {
            maybeResolveDnsForCell(row, 1, p.srcIp);
            maybeResolveDnsForCell(row, 2, p.dstIp);
        }
    }

    // Re-enable updates
    table->setUpdatesEnabled(true);
    table->viewport()->update();
}

void MainWindow::onStatsTick() {

    // Show packets/sec
    ppsLbl->setText(QString("PPS: %1").arg(packetsThisSecond));

    // Push into chart
    if (ppsChart) ppsChart->pushValue(packetsThisSecond);

    // Update top lists
    topSrcLbl->setText("Top SRC:\n" + formatTop(srcCount, 5));
    topDstLbl->setText("Top DST:\n" + formatTop(dstCount, 5));
    topPortsLbl->setText("Top DPorts:\n" + formatTopPorts(dportCount, 5));

    // Reset counters
    packetsThisSecond = 0;
    srcCount.clear();
    dstCount.clear();
    dportCount.clear();
}

QString MainWindow::formatTop(const QHash<QString,int>& map, int topN) {
    if (map.isEmpty()) return "-";

    // Convert map to vector for sorting by count
    QVector<QPair<QString,int>> v;
    v.reserve(map.size());
    for (auto it = map.begin(); it != map.end(); ++it) v.push_back({it.key(), it.value()});

    std::sort(v.begin(), v.end(), [](auto& a, auto& b){ return a.second > b.second; });  // Sort descending by count

    // Build display string
    QString out;
    int n = std::min(topN, (int)v.size());
    for (int i = 0; i < n; i++) {
        out += QString("%1) %2  (%3)\n").arg(i+1).arg(v[i].first).arg(v[i].second);
    }
    if (!out.isEmpty()) out.chop(1);
    return out;
}

QString MainWindow::formatTopPorts(const QHash<int,int>& map, int topN) {
    if (map.isEmpty()) return "-";

    // Convert map to vector for sorting by count
    QVector<QPair<int,int>> v;
    v.reserve(map.size());
    for (auto it = map.begin(); it != map.end(); ++it) v.push_back({it.key(), it.value()});

    std::sort(v.begin(), v.end(), [](auto& a, auto& b){ return a.second > b.second; });  // Sort descending by count


    // Build display string
    QString out;
    int n = std::min(topN, (int)v.size());
    for (int i = 0; i < n; i++) {
        out += QString("%1) %2  (%3)\n").arg(i+1).arg(v[i].first).arg(v[i].second);
    }
    if (!out.isEmpty()) out.chop(1);
    return out;
}

QString MainWindow::protoToString(L4Proto p) const {
    // Convert enum to readable text for the table
    switch (p) {
        case L4Proto::TCP: return "TCP";
        case L4Proto::UDP: return "UDP";
        case L4Proto::ICMP: return "ICMP";
        default: return "OTHER";
    }
}

QString MainWindow::buildBpfFilter() const {

    // Build protocol
    QStringList protoParts;
    if (tcpCb->isChecked()) protoParts << "tcp";
    if (udpCb->isChecked()) protoParts << "udp";
    if (icmpCb->isChecked()) protoParts << "icmp";

    QString protoExpr;
    if (!protoParts.isEmpty())
        protoExpr = "(" + protoParts.join(" or ") + ")";


    // Host and port
    QString host = hostEdit->text().trimmed();
    QString port = portEdit->text().trimmed();

    QStringList parts;
    if (!protoExpr.isEmpty()) parts << protoExpr;
    if (!host.isEmpty()) parts << QString("host %1").arg(host);

    if (!port.isEmpty()) {
        bool ok = false;
        int p = port.toInt(&ok);
        if (ok && p > 0 && p <= 65535)
            parts << QString("port %1").arg(p);
    }

    // Join all parts
    return parts.join(" and ");
}

void MainWindow::applyFilterToEngine() {
    // Apply current filter
    QString f = buildBpfFilter();
    engine.setBpfFilter(f);
}


// CSV Export
void MainWindow::exportCsv() {

    // Check if the table is empty
    if (table->rowCount() == 0) {
        QMessageBox::information(this, "Export CSV", "Table is empty.");
        return;
    }


    // Output file path
    QString fileName = QFileDialog::getSaveFileName(
        this,
        "Export CSV",
        "packets.csv",
        "CSV Files (*.csv)"
    );
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export CSV", "Cannot write file.");
        return;
    }

    QTextStream out(&file);

    // Header
    QStringList headers;
    headers.reserve(table->columnCount());
    for (int c = 0; c < table->columnCount(); c++) {
        auto* h = table->horizontalHeaderItem(c);
        headers << (h ? h->text() : QString("Col%1").arg(c));
    }
    out << headers.join(",") << "\n";

    // Rows
    for (int r = 0; r < table->rowCount(); r++) {
        QStringList row;
        row.reserve(table->columnCount());
        for (int c = 0; c < table->columnCount(); c++) {
            QTableWidgetItem* it = table->item(r, c);
            QString val = it ? it->text() : "";
            val.replace("\"", "\"\""); // escape quotes
            row << "\"" + val + "\"";
        }
        out << row.join(",") << "\n";
    }

    file.close();

    statusLbl->setText("CSV exported successfully.");
    statusLbl->setStyleSheet("QLabel { color: #1a7f37; font-weight: 600; }");
}

// DNS helpers
void MainWindow::maybeResolveDnsForCell(int row, int col, const QString& ip) {
    if (ip.isEmpty()) return;

    // Use cache if available
    if (dnsCache.contains(ip)) {
        const QString name = dnsCache.value(ip);
        if (!name.isEmpty()) applyDnsResultToCell(row, col, ip, name);
        return;
    }

    if (dnsInFlight.value(ip, false)) return;
    dnsInFlight[ip] = true;

    // Async reverse DNS lookup
    QHostInfo::lookupHost(ip, this, [this, ip, row, col](const QHostInfo& info) {
        dnsInFlight[ip] = false;

        QString name;
        if (info.error() == QHostInfo::NoError) name = info.hostName();
        dnsCache.insert(ip, name);  // Store result 

        if (!name.isEmpty()) applyDnsResultToCell(row, col, ip, name);
    });
}

void MainWindow::applyDnsResultToCell(int row, int col, const QString& ip, const QString& name) {
    if (row < 0 || row >= table->rowCount()) return;

    auto* item = table->item(row, col);
    if (!item) return;
    if (item->text() != ip) return;

    item->setText(QString("%1 (%2)").arg(ip, name));
}
