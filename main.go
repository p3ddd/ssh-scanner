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
	user       string
	password   string
	workers    int
	timeout    time.Duration
	port       int
	outputFile string
)

func init() {
	flag.StringVar(&user, "u", "test", "SSH username")
	flag.StringVar(&password, "p", "123456", "SSH password")
	flag.IntVar(&workers, "w", 100, "Number of concurrent workers")
	flag.DurationVar(&timeout, "t", 3*time.Second, "SSH connection timeout")
	flag.IntVar(&port, "P", 22, "SSH port")
	flag.StringVar(&outputFile, "o", "", "Output file for successful IPs")
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

	// Use a channel for IPs to save memory on large ranges
	ips := generateIPs(ip, ipNet)
	fmt.Printf("Scanning %s with %d workers on port %d...\n", cidr, workers, port)

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

func generateIPs(ip net.IP, ipNet *net.IPNet) chan string {
	out := make(chan string, workers*2) // Buffer slightly to keep workers busy
	go func() {
		defer close(out)

		// Ensure we are working with 4-byte IP for IPv4 to avoid confusion
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}

		// ip.Mask(ipNet.Mask) gives the network address.
		// We clone it because we modify it in the loop.
		currentIP := make(net.IP, len(ip))
		copy(currentIP, ip.Mask(ipNet.Mask))

		// Iterate through the range
		for ; ipNet.Contains(currentIP); inc(currentIP) {
			// Skip network and broadcast addresses for typical subnets if desired.
			// For simplicity and to match previous behavior, we'll just emit everything
			// but we can refine this.
			// The previous logic skipped the first and last if len > 2.
			// It's harder to know "len" upfront without calculation.
			// Let's just emit all valid IPs in the range.
			// If strict subnet scanning is needed, we can check if it's network/broadcast.

			// Note: The previous logic had a bug/feature where it skipped the first and last
			// IP of the range if the range had more than 2 IPs.
			// This usually skips .0 and .255 for a /24.
			// To replicate this exactly with a channel is tricky without knowing the size.
			// However, scanning .0 and .255 usually just fails or is harmless.
			// We will yield all IPs to be safe and simple.
			out <- currentIP.String()
		}
	}()
	return out
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func scan(ips chan string) {
	var (
		wg             sync.WaitGroup
		failNum, okNum atomic.Int32
		sem            = make(chan struct{}, workers)
		outputMutex    sync.Mutex
		f              *os.File
		err            error
	)

	if outputFile != "" {
		f, err = os.Create(outputFile)
		if err != nil {
			fmt.Printf("Failed to create output file: %v\n", err)
			return
		}
		defer f.Close()
	}

	for ip := range ips {
		wg.Add(1)
		sem <- struct{}{} // Acquire token
		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-sem }() // Release token

			addr := fmt.Sprintf("%s:%d", targetIP, port)
			if err := tryConnectSSH(addr, user, password); err == nil {
				fmt.Printf("[+] %s\n", targetIP)
				okNum.Add(1)

				if f != nil {
					outputMutex.Lock()
					f.WriteString(targetIP + "\n")
					outputMutex.Unlock()
				}
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
