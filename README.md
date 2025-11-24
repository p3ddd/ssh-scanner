# ssh-scanner

A high-performance SSH scanner written in Go. It scans specified network ranges or IPs to check for SSH accessibility using provided credentials.

## Build

```bash
go build -o ssh-scanner
```

## Usage

```bash
./ssh-scanner [options] <CIDR|IP|Suffix> [user] [password]
```

### Options

| Flag | Description                  | Default  |
| ---- | ---------------------------- | -------- |
| `-u` | SSH username                 | `test`   |
| `-p` | SSH password                 | `123456` |
| `-w` | Number of concurrent workers | `100`    |
| `-t` | Connection timeout           | `3s`     |

### Features

- **High Performance**: Concurrent scanning with adjustable worker count.
- **Smart Parsing**: Supports CIDR, single IPs, and suffix shortcuts (e.g., `3` -> `192.168.3.0/24`).
- **User Friendly**: Colored output, real-time progress bar, and detailed statistics.

### Examples

**Scan a subnet:**

```bash
./ssh-scanner 192.168.1.0/24
```

**Scan with custom credentials (Flags):**

```bash
./ssh-scanner -u admin -p secret -w 500 10.0.0.0/16
```

**Scan with custom credentials (Positional - Legacy Support):**

```bash
./ssh-scanner 192.168.1.0/24 admin secret
# Or using the shortcut:
./ssh-scanner 3 root 123456
```
