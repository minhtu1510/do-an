# ICSScout

**Industrial Control Systems Reconnaissance Framework**

A comprehensive, multi-protocol security assessment tool for OT/ICS environments, designed for passive reconnaissance and vulnerability analysis of industrial control systems.

## 🎯 Purpose

ICSScout is designed for **authorized security assessments** of industrial control systems in critical infrastructure environments such as:
- Power plants (hydro, thermal, nuclear)
- Manufacturing facilities
- Water treatment plants
- Oil & gas facilities
- Building automation systems

## ✨ Key Features

### Multi-Protocol Support
- **Siemens S7** (S7-300/400/1200/1500)
- **S7-PLUS** (encrypted protocol)
- **Siemens Logo!** controllers
- **Modbus TCP/RTU**
- **OPC UA** (Open Platform Communications Unified Architecture)
- **Profinet DCP** (discovery protocol)
- Support for additional protocols coming soon

### 🔍 Passive Reconnaissance (Priority Mode)
- **Packet Capture & Analysis** - Non-intrusive traffic monitoring
- **Protocol Detection** - Automatic identification of industrial protocols
- **Device Discovery** - Passive network scanning
- **Traffic Statistics** - Real-time analysis of communication patterns
- **PCAP Export** - Save captures for offline analysis

### 🛡️ Vulnerability Assessment
- **CVE Scanner** - Check devices against known vulnerabilities
- **Security Weakness Detection** - Identify common misconfigurations
- **Default Credentials Check** - Test for factory default passwords
- **Compliance Assessment** - Check against IEC 62443 and NIST CSF standards

### 📊 Advanced Analysis
- **Memory Dumper** - Safe extraction of PLC memory (with safety checks)
- **Behavior Monitoring** - Establish baselines and detect anomalies
- **Device Fingerprinting** - Identify OS, firmware versions
- **Communication Mapping** - Visualize device-to-device communications

### 💻 Dual Interfaces
- **CLI** - Interactive command-line interface with guided workflow
- **Web GUI** - Real-time dashboard with WebSocket updates

### 🛡️ Safety-First Design
- **Read-Only Mode** - Default safe operation mode
- **Safety Checks** - Pre-operation risk assessment
- **Confirmation Prompts** - Prevent accidental operations
- **Audit Trail** - Complete logging of all operations

## 📦 Installation

### Prerequisites

**Linux (Recommended):**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip python3-dev libpcap-dev

# Grant packet capture capabilities (alternative to running as root)
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)

# Or use Fedora/RHEL
sudo dnf install python3 python3-pip python3-devel libpcap-devel
```

**Windows:**
```powershell
# Install Python 3.9+ from python.org
# Install Npcap from https://npcap.com/ (required for packet capture)
# Run PowerShell as Administrator for network scanning
```

### Install ICSScout

```bash
# Clone repository
cd S7.Pwn

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r icsscout_requirements.txt

# Install ICSScout
pip install -e .
```

## 🚀 Quick Start

### CLI Mode

```bash
# Start ICSScout CLI
python -m icsscout.interfaces.cli.app

# Or if installed as package
icsscout
```

### Basic Workflow

```bash
# 1. Passive network discovery
icsscout> passive-scan --network 192.168.1.0/24 --duration 300

# 2. List discovered devices
icsscout> list-devices

# 3. Select a target
icsscout> select-target 1

# 4. Probe target for details
icsscout> probe

# 5. Start traffic capture
icsscout> capture start --duration 600 --output capture.pcap

# 6. Analyze captured traffic
icsscout> traffic-stats

# 7. Scan for vulnerabilities
icsscout> vuln-scan --target current

# 8. Generate report
icsscout> report generate --format html
```

### Web GUI Mode

```bash
# Start Web GUI
python -m icsscout.interfaces.web.app

# Or
icsscout --web

# Access at: http://127.0.0.1:5000
# Default credentials: admin / (set on first run)
```

## 📖 Documentation

Comprehensive documentation is available in the `/docs` directory:

- [User Guide](docs/USER_GUIDE.md) - Complete usage instructions
- [Protocol Guide](docs/PROTOCOLS.md) - Protocol-specific information
- [API Reference](docs/API.md) - Programmatic usage
- [Security Best Practices](docs/SECURITY.md) - Safe usage guidelines

## ⚠️ Legal & Safety Disclaimer

**IMPORTANT:**

- ✅ **Only use on systems you own or have explicit written authorization to test**
- ⚠️ **Critical infrastructure requires extreme caution**
- 🛡️ **Always use READ-ONLY mode in production environments**
- 📝 **Maintain detailed audit logs**
- 🚫 **Never use for unauthorized access or malicious purposes**

The developers assume no liability for misuse or damage caused by this tool.

## 🏗️ Architecture

```
icsscout/
├── core/              # Core business logic
│   ├── protocols/     # Protocol implementations
│   ├── scanner/       # Network scanning
│   ├── capture/       # Packet capture & analysis
│   ├── vulnerability/ # CVE scanning
│   ├── memory/        # Memory operations
│   ├── monitoring/    # Behavior monitoring
│   └── safety/        # Safety mechanisms
├── domain/            # Domain models
├── services/          # Application services
├── interfaces/        # User interfaces (CLI/Web)
├── infrastructure/    # Infrastructure (DB, config)
├── utils/             # Utilities
└── data/              # Data files (CVE DB, fingerprints)
```

## 🔧 Configuration

Configuration file: `icsscout/data/config.yaml`

```yaml
project:
  name: "ICSScout"
  mode: "passive"  # passive / active / safe

safety:
  read_only_mode: true
  require_confirmation: true

protocols:
  s7:
    enabled: true
  modbus:
    enabled: true
  opcua:
    enabled: true
```

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 👥 Authors

- ICSScout Development Team
- Original S7.Pwn by: [Original Author]

## 🙏 Acknowledgments

- **python-snap7** - Siemens S7 protocol library
- **pymodbus** - Modbus protocol implementation
- **opcua/asyncua** - OPC UA implementation
- **scapy** - Packet manipulation library

## 📞 Support

- Issues: [GitHub Issues](https://github.com/yourusername/icsscout/issues)
- Documentation: [Wiki](https://github.com/yourusername/icsscout/wiki)
- Email: security@yourorganization.com (for responsible disclosure)

---

**Version:** 2.0.0
**Status:** Active Development
**Last Updated:** 2025-01-05
