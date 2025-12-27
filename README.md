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

## 🛠 Installation (Windows)

### 1) Install Npcap

Download and install **Npcap** for Windows.

During installation:
- Enable **WinPcap-compatible mode** (recommended)
- Administrator rights may be required

Npcap is required for live packet capture.

---

### 2) Download Npcap SDK

Download **Npcap SDK (ZIP)** and extract it to a local folder, for example:

```bash
E:/NpcapSDK
```

After extraction, you should have:

```bash
E:/NpcapSDK/Include/pcap.h

E:/NpcapSDK/Lib/x64/wpcap.lib

E:/NpcapSDK/Lib/x64/Packet.lib
```


This SDK is required for compiling the application.

---

### 3) Install Qt 6 (MSVC)

Install **Qt 6.x** using the **Qt Online Installer**.

Make sure to install:
- Qt version built for **msvc2022_64**
- Qt Widgets
- Qt Network

---

### 4) Install Visual Studio build tools

Install **Visual Studio** (or Visual Studio Build Tools) with:
- Desktop development with C++
- MSVC toolset
- Windows SDK
- CMake tools

---

## ⚙ Build Instructions (VS Code / CMake)

### 1) Clone repository

Clone the repository and open the **PacketAnalyzer** folder in VS Code.

```bash
git clone https://github.com/YOUR-USERNAME/Network-Packet-Analyzer.git
```
---

### 2) Configure Qt paths locally (do NOT commit these)

This project uses Qt 6 + CMake.
Qt installation paths differ per machine, therefore they must NOT be committed to GitHub.

Steps in VS Code:

1. Open the project folder in VS Code
2. Create (or edit) the file:

```bash
.vscode/settings.json
```

3. Add the following content (example):

```bash
{
  "cmake.configureSettings": {
    "CMAKE_PREFIX_PATH": "E:/qt_ceva/altceva/6.10.1/msvc2022_64",
    "Qt6_DIR": "E:/qt_ceva/altceva/6.10.1/msvc2022_64/lib/cmake/Qt6"
  },
  "cmake.environment": {
    "PATH": "E:/qt_ceva/altceva/6.10.1/msvc2022_64/bin;${env:PATH}"
  }
}
```

🔹 IMPORTANT:

- Replace the paths above with the location where Qt is installed on your system

- The .vscode/ folder is intentionally ignored and must NOT be pushed to GitHub

---

### 3) Build

In VS Code:

- Open Command Palette: **Ctrl + Shift + P**

- Run:

  - CMake: Delete Cache and Reconfigure
  - CMake: Build

---

### 4) Run (VS Code – Recommended)

⚠ Packet capture requires administrator privileges.

Recommended method:

1. Close VS Code

2. Reopen VS Code as Administrator

3. Open the project

4. Press **Ctrl + Shift + P**

5. Run:

   - CMake: Run

The application will start with administrator privileges and packet capture will work correctly.

---

## ▶ Running Notes

- Running as Administrator is required, otherwise packet capture may fail or show no traffic

- Loopback capture works if Npcap supports it and the loopback adapter is selected

- CSV export contains only the packets displayed in the table, not raw PCAP data

---

## ⚠ Important Notes

- .vscode/ and build/ are intentionally ignored (local configuration differs per machine)

- Npcap must be installed on Windows before running the application

- Qt paths are local per user and must not be committed
