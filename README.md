# Network Packet Analyzer (C++ / Qt) – Desktop GUI Packet Sniffer

Network Packet Analyzer is a desktop packet capture and analysis tool built in **C++** using **Qt 6 Widgets** and **Npcap/libpcap**.  
It captures packets in real time, displays them in a table, supports **BPF filtering**, optional **DNS resolving**, live **PPS graph**, **Top IPs/Ports statistics**, and **CSV export**.

---

## 🚀 Features

### 📡 Real-time Packet Capture
- Captures live traffic via **Npcap** (Windows).
- Interface selection (Ethernet/Wi-Fi/Loopback, etc.).
- Start/Stop capture from GUI.

### 🧪 BPF Filtering (Real pcap filter)
Apply filters using `pcap_compile()` + `pcap_setfilter()`:
- Protocol checkboxes: **TCP**, **UDP**, **ICMP**
- Optional filters:
  - `host 8.8.8.8`
  - `port 443`
  - Combined examples:
    - `tcp and port 443`
    - `udp and port 53`
    - `(tcp or udp) and host 8.8.8.8`

### 🧾 Professional Packet Columns
Table includes:
- Time
- Source IP / Destination IP
- Protocol (TCP/UDP/ICMP/OTHER)
- SourcePort / DestinationPort
- Length
- Information (e.g. TCP flags, ARP who-has, ICMP type/code)

### 📊 Live Statistics
- PPS (packets per second) label
- PPS chart (last 60 seconds)
- Top SRC IPs
- Top DST IPs
- Top destination ports

### 🌐 DNS Resolve (Optional)
- Checkbox: Resolve DNS
- Uses Qt Network (`QHostInfo`) to resolve hostnames for IPs

### 📁 Export
- Export packets from the table to **CSV** (one click)

---

## 🧩 Tech Stack

| Component | Technology |
|----------|------------|
| Language | C++17 |
| UI | Qt 6 Widgets |
| DNS | Qt 6 Network (QHostInfo) |
| Capture | Npcap (WinPcap-compatible) |
| Build System | CMake |
| IDE | VS Code / Visual Studio |

---

## 📂 Project Structure

```bash
PacketAnalyzer/
│
├── core/
│   ├── PacketInfo.h            # Packet struct + protocol enums
│   ├── CaptureEngine.h         # Capture engine interface (pcap)
│   └── CaptureEngine.cpp       # Packet parsing + capture loop
│
├── ui/
│   ├── main.cpp                # Qt entry point
│   ├── MainWindow.h            # GUI definitions
│   ├── MainWindow.cpp          # GUI logic, filters, stats, export
│   ├── PpsChart.h              # Simple chart widget
│   └── PpsChart.cpp            # PPS drawing logic
│
├── CMakeLists.txt
├── .gitignore
└── README.md
```

##🛠 Installation (Windows)
1) Install Npcap

Download and install Npcap installer for Windows:

Install in WinPcap-compatible mode (recommended)

Admin rights may be required

2) Download Npcap SDK

Download Npcap SDK (ZIP) and extract it somewhere (example):

E:/NpcapSDK


You should have:

E:/NpcapSDK/Include/pcap.h

E:/NpcapSDK/Lib/x64/wpcap.lib

E:/NpcapSDK/Lib/x64/Packet.lib

3) Install Qt 6 (MSVC)
Install Qt 6.x for msvc2022_64 using Qt Online Installer.

4) Install Visual Studio build tools

Install Visual Studio (or Build Tools) with:
Desktop development with C++
MSVC toolset
Windows SDK
CMake tools
