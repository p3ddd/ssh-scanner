package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	user     string
	password string
	workers  int
	timeout  time.Duration
)

func init() {
	flag.StringVar(&user, "u", "test", "SSH username")
	flag.StringVar(&password, "p", "123456", "SSH password")
	flag.IntVar(&workers, "w", 100, "Number of concurrent workers")
	flag.DurationVar(&timeout, "t", 3*time.Second, "SSH connection timeout")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <cidr>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s -u admin -p password -w 200 192.168.1.0/24\n", os.Args[0])
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	cidr := flag.Arg(0)
	ip, ipNet, err := parseInput(cidr)
	if err != nil {
		fmt.Printf("Invalid CIDR or IP: %v\n", err)
		os.Exit(1)
	}

	ips := generateIPs(ip, ipNet)
	fmt.Printf("Scanning %d IPs in %s with %d workers...\n", len(ips), cidr, workers)

	scan(ips)
}

func parseInput(input string) (net.IP, *net.IPNet, error) {
	// Check if input is a single integer (backward compatibility)
	// e.g. "3" -> "192.168.3.0/24"
	if _, err := strconv.Atoi(input); err == nil {
		input = fmt.Sprintf("192.168.%s.0/24", input)
	}

	ip, ipNet, err := net.ParseCIDR(input)
	if err != nil {
		// Try to parse as single IP
		if ip := net.ParseIP(input); ip != nil {
			input = input + "/32"
			_, ipNet, err = net.ParseCIDR(input)
			return ip, ipNet, err
		}
		return nil, nil, err
	}
	return ip, ipNet, nil
}

func generateIPs(ip net.IP, ipNet *net.IPNet) []string {
	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// Remove network address and broadcast address if it's a subnet?
	// Usually for /24, .0 and .255 are not hosts.
	// But for /32 or /31 it might be different.
	// For simplicity, we scan everything in the range.
	// Actually, standard behavior is usually to skip network and broadcast for typical subnets.
	// But let's keep it simple and scan all for now, or maybe just skip if len > 2.
	if len(ips) > 2 {
		return ips[1 : len(ips)-1]
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func scan(ips []string) {
	var (
		wg             sync.WaitGroup
		failNum, okNum atomic.Int32
		sem            = make(chan struct{}, workers)
	)

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{} // Acquire token
		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-sem }() // Release token

			addr := fmt.Sprintf("%s:22", targetIP)
			if err := tryConnectSSH(addr, user, password); err == nil {
				fmt.Printf("[+] %s\n", targetIP)
				okNum.Add(1)
			} else {
				failNum.Add(1)
			}
		}(ip)
	}

	wg.Wait()
	fmt.Println("--------------------")
	fmt.Println("[+]", okNum.Load(), "[-]", failNum.Load())
}

func tryConnectSSH(addr, user, password string) error {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return err
	}
	client.Close()
	return nil
}
