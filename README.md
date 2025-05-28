<!--
KEYWORDS: MAC flooder, MAC flooding tool, MAC address table overflow, Ethernet attack, switch flooding, network security testing, MAC spoofing, MAC table attack, Layer 2 attack, network penetration testing, Python MAC flood, MAC address injection, switch DoS, MAC table poisoning, network audit, security tool, ethical hacking, penetration test, L2 MAC flood, broadcast storm, custom Ethernet frame, raw socket, Linux network tool
-->

# mac_injection.py




## Description

**mac_injection.py** is a tool designed to overwhelm a router or switch by flooding its MAC address table with many fake Ethernet frames. This can disrupt network connectivity on some old or unconfigured devices.

---

## Features

- Sends Ethernet frames with random or custom MAC addresses.
- Supports different payload patterns: random, zero, ff, increment, custom, counter.
- Can randomize EtherType field (accepts names like `ipv4`, `arp`, `vlan`, hex values, or `'auto'`).
- Multi-process support for higher speed.
- Can use custom payload in hex or ASCII format.
- Stealth mode: adds jitter (random delay) and uses ternary payloads (only 0x00, 0x01, 0x02).

---
## Installation

1. Clone the repository:

   ```shell
   https://github.com/xDavunix05/L2-Macflood-tool.git
   ```

2. Navigate to the project directory:

   ```shell
   cd L2-Macflood-tool
   ```

3. Execute the script using Python 3:

   ```shell
   python3 mac_injection.py
   ```
---

## OS / Kernel Support

- **Linux Kernel** (required for raw socket support)
- **Windows:** Not supported
- **macOS:** Not supported
- **BSD variants:** Not supported
- **WiFi cards are not compatible** with this MAC flooder tool; only Ethernet interfaces are supported.

---

## Usage

```sh
sudo python3 mac_injection.py -i eth0
sudo python3 mac_injection.py -i eth0 -s auto -t 8 --payload-mode ff --ether-type arp
sudo python3 mac_injection.py --help   # Show help message
```

---

## Options

| Option                        | Description                                                                                      |
|-------------------------------|--------------------------------------------------------------------------------------------------|
| `-i`, `--interface`           | Network interface to use (e.g., eth0). **(Required)**                                            |
| `-d`, `--dstmac`              | Destination MAC address (default: broadcast).                                                    |
| `-s`, `--size`                | Payload size in bytes (min 46, max 1450), or `'auto'` for random size.                           |
| `-c`, `--count`               | Number of frames per process (0 = unlimited).                                                    |
| `-t`, `--threads`             | Number of parallel processes to use.                                                             |
| `-v`, `--interval`            | Delay between frames in seconds (default: 0).                                                    |
| `--ether-type`                | EtherType value (e.g., ipv4, arp, vlan, hex like 0x0800, or `'auto'` for random).                |
| `--payload-mode`              | Payload pattern: `random`, `zero`, `ff`, `inc`, `custom`, `counter`.                             |
| `--custom-hex`                | Custom payload as hex string (e.g., 'AA DD' or 'AA:DD'). Use with `--payload-mode custom`.       |
| `--custom-ascii`              | Custom payload as ASCII string. Use with `--payload-mode custom`.                                |
| `--stealth`                   | Enable stealth mode:<br>• Adds jitter (random delay between packets)<br>• Uses ternary payloads (only 0x00, 0x01, 0x02) |
| `-h`, `--help`                | Show help message and exit.                                                                      |

---

## Disclaimer

- Use this tool **ONLY** on routers or switches you own or have explicit permission to test.
- **Unauthorized use is unethical and illegal.**
- MAC table overflow attacks from this tool may only affect a small number of outdated or improperly configured switches or routers that do not limit MAC addresses.

---

## License

**This script is provided "as-is". Use it at your own risk. The author is not responsible for any issues that may arise from using this script.**

MIT License  
See the [LICENSE](LICENSE) file for more details.

---
