# CodeAlpha — Basic Network Sniffer

A high-performance, modular, and security-oriented network packet sniffer and protocol analyzer developed in Python. Built for network diagnostics, security monitoring, forensic traffic capture, and educational protocol inspection.

Developed for the **CodeAlpha Cyber Security Internship — Task 1**.

---

## 📌 Problem Statement

Modern networks exchange vast amounts of telemetry, control messages, and application data every second. Security analysts and network engineers require visibility into raw packet headers to detect misconfigurations, anomalous port activity, unencrypted credentials, and unauthorized communications. Building a custom network sniffer provides deep foundational insight into the TCP/IP stack, packet encapsulation, framing, and low-level socket programming.

---

## 🎯 Objectives

- Capture raw link-layer and network-layer packets from local network adapters.
- Dissect core protocols across Layer 2 (Ethernet, ARP), Layer 3 (IPv4, IPv6), Layer 4 (TCP, UDP, ICMP), and Layer 7 (DNS, HTTP).
- Support dual filtering mechanisms: **Kernel-level BPF (Berkeley Packet Filters)** and **Application-level Display Filters**.
- Guarantee zero data loss during parsing by persisting raw binary packets to `.pcap` files **prior** to userland dissection.
- Maintain a strictly constant $O(1)$ memory footprint using streaming generators.
- Provide real-time forensic statistics, protocol distributions, and top-communicating endpoint reports.
- Include an offline analysis mode (`--read-pcap`) enabling inspection without requiring administrative privileges.

---

## 🛠️ Technologies & Dependencies

- **Language**: Python 3.10+
- **Packet Engine**: [Scapy](https://scapy.net/) (Promiscuous packet capture, BPF compilation, raw byte dissection)
- **Terminal UI & Styling**: [Rich](https://github.com/Textualize/rich) (ANSI styling, dynamic tables, and forensic summary panels)
- **Packet Driver**: [Npcap](https://npcap.com/) (Windows packet capture library) / Libpcap (Linux/macOS)
- **Testing Framework**: [pytest](https://pytest.org/) (Automated validation using synthetic packet vectors)

---

## 📐 Architecture & Pipeline

The capture engine follows a decoupled, resilient pipeline designed to prevent data loss even if malformed packets or zero-day extensions are encountered:

```
[ CLI Arguments ] ──> [ Validate Config & Privileges ] ──> [ Resolve Network Interface ]
                                                                      │
                                                                      ▼
                                                       [ scapy.sniff(store=False) ]
                                                                      │ (one raw packet at a time)
                                      ┌───────────────────────────────┴───────────────────────────────┐
                                      ▼                                                               ▼
                        [ PcapWriter (stream to disk) ]                                     [ parse_packet() ]
                         *Written first to preserve                                         *Extracts Layer 2-7
                          forensic evidence on disk                                          into PacketRecord
                                                                                                      │
                                                                                                      ▼
                                                                                            [ Display Filter ]
                                                                                                      │
                                                                                  ┌───────────────────┴───────────────────┐
                                                                                  ▼                                       ▼
                                                                         [ Formatter (Console) ]               [ Session Telemetry ]
                                                                                                               *stats.update()
                                                                                                                          │
                                                                                                                          ▼
                                                                                                              [ Ctrl+C / Timeout / Limit ]
                                                                                                                          │
                                                                                                                          ▼
                                                                                                              [ Summary Report & Metrics ]
```

### Architectural Highlights:
1. **Evidence Preservation**: Packets are written to the `.pcap` file *before* protocol parsing. An unhandled parser exception will never drop or corrupt recorded forensic traffic.
2. **Constant Memory ($O(1)$)**: By enforcing `store=False`, packets are processed sequentially and discarded from RAM immediately after analysis.
3. **Resilient Parsing**: Malformed or truncated packets are safely caught, increments the `malformed` counter, and do not crash the sniffer loop.

---

## 📦 Project Structure

```text
CodeAlpha_BasicNetworkSniffer/
├── src/
│   ├── __init__.py        # Package initialization
│   ├── models.py          # PacketRecord dataclass definition
│   ├── parser.py          # Layer dissection (Ethernet, ARP, IP, TCP, UDP, ICMP, DNS)
│   ├── sniffer.py         # Capture lifecycle, PcapWriter, and offline reader
│   ├── formatter.py       # Rich CLI presentation and protocol color mapping
│   ├── stats.py           # Capture metrics, throughput, and session statistics
│   └── utils.py           # Admin privilege checks and interface resolution
├── tests/
│   ├── __init__.py
│   └── test_parser.py     # Unit tests verifying dissectors on synthetic frames
├── captures/              # Sample capture files (.pcap)
│   └── sample_demo.pcap
├── main.py                # Command-line entry point
├── requirements.txt       # Python dependencies
├── pytest.ini             # Test runner configuration
└── README.md              # Project documentation
```

---

## 🚀 Installation & Prerequisites

### 1. Install Npcap (Windows Only)
On Windows, raw packet sniffing requires the **Npcap** packet capture driver:
1. Download Npcap from [npcap.com](https://npcap.com/#download).
2. During installation, ensure the option **"Install Npcap in WinPcap API-compatible Mode"** is checked.

### 2. Clone the Repository & Install Dependencies
```powershell
git clone https://github.com/<your-username>/CodeAlpha_BasicNetworkSniffer.git
cd CodeAlpha_BasicNetworkSniffer

# (Optional) Create and activate virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt
```

---

## 💻 Usage & Command-Line Reference

> **Important Note for Live Capture on Windows**: Packet capture requires administrative permissions. Open PowerShell or Command Prompt as **Administrator** before executing live capture commands.

### Command-Line Arguments:

| Argument | Long Flag | Description |
| :--- | :--- | :--- |
| `-i` | `--interface` | Interface index or name (e.g., `-i 1` or `-i "Wi-Fi"`) |
| `-l` | `--list-interfaces`| Display available network interfaces with IP/MAC and exit |
| `-f` | `--filter` | Berkeley Packet Filter (BPF) capture filter string |
| `-w` | `--write-pcap` | File path to write captured packets as `.pcap` |
| `-r` | `--read-pcap` | Path to existing `.pcap` file for offline analysis |
| `-c` | `--count` | Maximum number of packets to capture before exiting |
| `-t` | `--timeout` | Capture session timeout in seconds |
| `-p` | `--protocol` | Application-level display filter (`TCP`, `UDP`, `ICMP`, `DNS`) |
| | `--no-admin-check` | Bypass administrator privilege pre-flight check |

---

## 🔍 Examples

### 1. List Available Interfaces
```powershell
python main.py --list-interfaces
```

### 2. Offline PCAP Analysis (Zero Privileges Required)
Inspect any existing `.pcap` file with real-time protocol decoding and forensic reports:
```powershell
python main.py -r captures/sample_demo.pcap
```

### 3. Display Filtering on PCAP
Display only ICMP or DNS packets from a captured file:
```powershell
python main.py -r captures/sample_demo.pcap -p ICMP
```

### 4. Live Capture on Selected Interface
```powershell
# Run in Administrator Terminal
python main.py -i 1 -c 50
```

### 5. Live Capture with Kernel-Level BPF Filter & PCAP Export
Filter specifically for DNS queries and write raw packets to disk:
```powershell
python main.py -i 1 -f "udp port 53" -w captures/dns_session.pcap
```

### 6. Filter for Web Traffic (HTTP / HTTPS)
```powershell
python main.py -i 1 -f "tcp port 80 or tcp port 443" -c 100
```

---

## 🔬 Protocol Dissection Explanation

| Protocol | OSI Layer | Fields Extracted | Cybersecurity Significance |
| :--- | :---: | :--- | :--- |
| **Ethernet / ARP** | Layer 2 | Hardware MAC addresses, OpCode (`Who has`, `Is at`) | Detecting ARP poisoning/spoofing, rogue gateway announcement, and Layer 2 MITM attacks. |
| **IPv4 / IPv6** | Layer 3 | Source IP, Destination IP, Payload Length, TTL | Identifying communication endpoints, unauthorized routing, and internal reconnaissance. |
| **TCP** | Layer 4 | Ports, Sequence/Ack numbers, Window Size, Control Flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`) | Identifying TCP port scans (SYN stealth scans), connection resets, and session states. |
| **UDP** | Layer 4 | Source Port, Destination Port, Datagram Length | Analyzing connectionless protocols, UDP flood attacks, and service discovery probes. |
| **ICMP** | Layer 3/4 | Message Type, Code (Echo Request, Echo Reply, Destination Unreachable, TTL Exceeded) | Identifying network mapping (`ping sweeps`), traceroute probes, and routing errors. |
| **DNS** | Layer 7 | Query/Response flag, Transaction ID, Queried Domain (`qname`), Answer count | Detecting DNS tunneling, data exfiltration, and malicious domain resolution. |
| **HTTP** | Layer 7 | Request methods (`GET`, `POST`, `PUT`), Target URI, Protocol Version | Identifying cleartext credential submissions and web-based exploits. |

---

## 📊 Example Console Output

```text
[*] OFFLINE PCAP INSPECTION: captures/sample_demo.pcap

    1 | 18:29:38.316 | TCP   |    192.168.1.10:51200  ->  93.184.216.34:80      |    54B | Seq=1000 Ack=0 Win=8192 [SYN]
    2 | 18:29:38.316 | TCP   |      93.184.216.34:80  ->  192.168.1.10:51200    |    54B | Seq=5000 Ack=1001 Win=8192 [SYN,ACK]
    3 | 18:29:38.316 | TCP   |    192.168.1.10:51200  ->  93.184.216.34:80      |    54B | Seq=1001 Ack=5001 Win=8192 [ACK]
    4 | 18:29:38.316 | HTTP  |    192.168.1.10:51200  ->  93.184.216.34:80      |   101B | Seq=1001 Ack=5001 Win=8192 | GET /index.html HTTP/1.1 [PSH,ACK]
    5 | 18:29:38.316 | DNS   |    192.168.1.10:55123  ->  8.8.8.8:53            |    71B | Standard query example.com. | Len=37
    6 | 18:29:38.317 | ICMP  |          192.168.1.10  ->  8.8.8.8               |    42B | Echo Request (Ping)
    7 | 18:29:38.317 | ICMP  |               8.8.8.8  ->  192.168.1.10          |    42B | Echo Reply (Ping Response)

┌─────────────────────────────────────────┐
│ [*] CAPTURE SESSION SUMMARY             │
│ • Total Duration   : 0.01 seconds       │
│ • Packets Captured : 7                  │
│ • Total Data Volume: 418.0 B            │
│ • Average Rate     : 927.1 packets/sec  │
└─────────────────────────────────────────┘

      Protocol Distribution      
┌──────────┬───────┬────────────┐
│ Protocol │ Count │ Percentage │
├──────────┼───────┼────────────┤
│ TCP      │     3 │      42.9% │
│ ICMP     │     2 │      28.6% │
│ HTTP     │     1 │      14.3% │
│ DNS      │     1 │      14.3% │
└──────────┴───────┴────────────┘

  Top Communicating Endpoints   
┌───────────────┬──────────────┐
│ IP Address    │ Packets Sent │
├───────────────┼──────────────┤
│ 192.168.1.10  │            5 │
│ 93.184.216.34 │            1 │
│ 8.8.8.8       │            1 │
└───────────────┴──────────────┘
```

---

## 🧪 Testing Methodology & Verification

A comprehensive test suite is included in `tests/test_parser.py`. Tests construct synthetic Scapy packets in memory and assert that layer decoders extract addresses, ports, flags, and diagnostic strings accurately without requiring live network access or elevated privileges.

### Running Unit Tests:
```powershell
python -m pytest -v
```

### Test Coverage:
- `test_parse_tcp_syn_packet`: Validates TCP flag decoding (`SYN`), ports, and sequence numbers.
- `test_parse_udp_packet`: Validates UDP endpoint extraction and datagram length.
- `test_parse_icmp_echo_request`: Validates ICMP type/code decoding for Ping diagnostic requests.
- `test_parse_dns_query`: Validates query parsing and domain name extraction.
- `test_parse_arp_packet`: Validates ARP opcode resolution and hardware mapping.

---

## 🔒 Security & Privacy Considerations

1. **Privilege Boundaries**: Raw packet sniffing interfaces directly with the kernel network stack and requires root/administrator privileges. Access must be restricted strictly to authorized administrators.
2. **Data Minimization**: The sniffer extracts metadata and protocol control headers. It avoids logging full encrypted payloads to minimize exposure of private user data.
3. **Storage Security**: Captured `.pcap` files may contain sensitive enterprise telemetry. Captured files should be stored in access-controlled storage and excluded from public version control.

---

## ⚠️ Limitations & Future Improvements

### Current Limitations:
- Encrypted traffic (TLS/HTTPS, SSH, IPsec) cannot be inspected beyond Layer 4 (ports and packet sizes) without proxy termination.
- High-throughput 10Gbps+ links require kernel-bypass architectures (such as DPDK or PF_RING) rather than standard Python userland sockets.

### Future Roadmap:
- [ ] Export session statistics to JSON / CSV formats for automated SIEM ingestion.
- [ ] Integration with GeoIP databases to resolve country/ASN for external endpoints.
- [ ] Real-time anomaly detection alerts (e.g. TCP SYN scan detection, DNS tunneling heuristic alerts).

---

## ⚖️ Ethical & Legal Disclaimer

This tool is designed solely for **authorized network diagnostics, cybersecurity education, and defensive security research**. Capturing or analyzing network traffic without explicit permission from the network owner is illegal under laws including the **Computer Fraud and Abuse Act (CFAA)** and equivalent global legislation. 

Always obtain prior written authorization before running packet capture utilities on any network.

