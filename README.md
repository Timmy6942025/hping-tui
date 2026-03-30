# hping-tui

> Interactive terminal UI for [hping3](http://wiki.kali.org/hping3) — configure, run, and monitor network packet tests from a beautiful terminal interface.

Built with [OpenTUI](https://github.com/anomalyco/opentui) and React.

![Version](https://img.shields.io/npm/v/hping-tui)
![License](https://img.shields.io/npm/l/hping-tui)
![Node](https://img.shields.io/node/v/hping-tui)

## Features

- **Interactive configuration** — Set target, port, protocol, TCP flags, TTL, data length, and more
- **Live output monitoring** — Color-coded output with timestamps, line filtering, and scrollback
- **Real-time statistics** — Packets sent/received, packet loss bar, RTT min/avg/max
- **6 built-in presets** — SYN Scan, Firewall Test, ICMP Ping, Traceroute, UDP Test, XMAS Scan
- **Persistent config** — Settings saved automatically between sessions
- **Log export** — Save session output to timestamped log files
- **Help overlay** — Full keyboard reference accessible from within the TUI

## Installation

```bash
npm install -g hping-tui
```

### Requirements

- **Node.js** >= 18 or **Bun** >= 1.0
- **hping3** installed and available in PATH
- **sudo** access (hping3 requires raw socket privileges)

#### Install hping3

```bash
# macOS
brew install hping

# Ubuntu / Debian
sudo apt install hping3

# Arch Linux
sudo pacman -S hping

# Fedora / RHEL
sudo dnf install hping3
```

## Usage

```bash
hping-tui
```

That's it. The TUI will launch and you can configure your hping3 session interactively.

## Keyboard Shortcuts

### Controls

| Key | Action |
|-----|--------|
| `Ctrl+R` | Start / restart hping3 |
| `Ctrl+S` | Stop running process |
| `Ctrl+O` | Save output to log file |
| `Ctrl+C` | Quit application |
| `Ctrl+H` | Toggle help screen |
| `Tab` | Cycle through input fields |
| `Enter` | Confirm field, move to next |
| `Backspace` | Delete character |

### Protocol

| Key | Action |
|-----|--------|
| `Ctrl+1` | TCP mode |
| `Ctrl+2` | UDP mode |
| `Ctrl+3` | ICMP mode |

### TCP Flags

| Key | Action |
|-----|--------|
| `s` | Toggle SYN |
| `a` | Toggle ACK |
| `f` | Toggle FIN |
| `r` | Toggle RST |
| `p` | Toggle PSH |
| `u` | Toggle URG |

### Options

| Key | Action |
|-----|--------|
| `Shift+F` | Toggle flood mode |
| `Shift+A` | Toggle fast mode |
| `Shift+T` | Toggle traceroute |
| `Shift+V` | Toggle verbose output |
| `Shift+N` | Toggle DNS resolution |

### Presets

| Key | Preset |
|-----|--------|
| `1` | SYN Scan |
| `2` | Firewall Test |
| `3` | ICMP Ping |
| `4` | Traceroute |
| `5` | UDP Test |
| `6` | XMAS Scan |

### Output Filters

| Key | Action |
|-----|--------|
| `Shift+R` | Toggle response lines |
| `Shift+S` | Toggle stats lines |
| `Shift+E` | Toggle error lines |
| `Shift+I` | Toggle info/header lines |

## Configuration

Settings are persisted to `~/.hping-tui/config.json` and automatically restored on next launch.

Logs are saved to `~/.hping-tui/hping-<timestamp>.log` when you press `Ctrl+O`.

## Layout

```
┌──────────────────────────────────────────────────────────────┐
│ hping-tui — Interactive hping3 Terminal UI            v1.0.0 │
├──────────────────────────────────────────────────────────────┤
│ [1] S SYN Scan  [2] F Firewall Test  [3] I ICMP Ping  ...    │
├────────────────────────────┬─────────────────────────────────┤
│ Configuration              │ Output                    ● Run │
│ Target:     192.168.1.1    │ ┌─────────────────────────────┐ │
│ Port:       80             │ │ [12:00:01] len=46 ip=...    │ │
│ Count:      10             │ │ [12:00:02] len=46 ip=...    │ │
│ Interval:   1              │ │ [12:00:03] len=46 ip=...    │ │
│ Data Len:   0              │ │ [12:00:04] len=46 ip=...    │ │
│ TTL:        64             │ │ ...                         │ │
│ Win Size:                  │ └─────────────────────────────┘ │
│ Spoof IP:                  │ Sent: 10  Recv: 10  Loss: 0%    │
│                            │ ██████████                      │
│ Protocol:                  │                                 │
│ [1] TCP  [2] UDP  [3] ICMP│                                 │
│ Flags:                     │                                 │
│ [s] SYN  [a] ACK  [f] FIN │                                 │
│ [r] RST  [p] PSH  [u] URG │                                 │
│ Options:                   │                                 │
│ [F] Flood  [A] Fast        │                                 │
│ [T] Traceroute  [V] Verbose│                                 │
├──────────────────────────────────────────────────────────────┤
│ hping3 -S -p 80 -c 10 -i 1 --ttl 64 192.168.1.1              │
│ Ctrl+R Start  Ctrl+S Stop  Ctrl+O Log  Tab Field  Ctrl+C Quit│
└──────────────────────────────────────────────────────────────┘
```

## Development

```bash
git clone https://github.com/Timmy6942025/hping-tui.git
cd hping-tui
bun install
bun run dev
```

### Building

```bash
bun run build
```

Output goes to `dist/`.

## License

MIT — see [LICENSE](./LICENSE)

## Author

Timothy — [GitHub](https://github.com/Timmy6942025)
