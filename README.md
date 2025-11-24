# ssh-scanner

A high-performance SSH scanner written in Go. It scans specified network ranges or IPs to check for SSH accessibility using provided credentials.

## Build

```bash
go build -o ssh-scanner
```

## Usage

```bash
./ssh-scanner [options] <CIDR|IP|Suffix>
```

### Options

| Flag | Description                  | Default  |
| ---- | ---------------------------- | -------- |
| `-u` | SSH username                 | `test`   |
| `-p` | SSH password                 | `123456` |
| `-w` | Number of concurrent workers | `100`    |
| `-t` | Connection timeout           | `3s`     |

### Examples

**Scan a subnet:**

```bash
./ssh-scanner 192.168.1.0/24
```

**Scan with custom credentials:**

```bash
./ssh-scanner -u admin -p secret -w 500 10.0.0.0/16
```

**Scan a single IP:**

```bash
./ssh-scanner 192.168.1.100
```

**Shortcut (scans `192.168.x.0/24`):**

```bash
./ssh-scanner 3  # Equivalent to 192.168.3.0/24
```
