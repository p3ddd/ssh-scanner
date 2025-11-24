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

// ANSI Color Codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
)

type Config struct {
	User       string
	Password   string
	Workers    int
	Timeout    time.Duration
	Port       int
	OutputFile string
	CIDR       string
}

func parseConfig() *Config {
	cfg := &Config{}
	flag.StringVar(&cfg.User, "u", "test", "SSH username")
	flag.StringVar(&cfg.Password, "p", "123456", "SSH password")
	flag.IntVar(&cfg.Workers, "w", 100, "Number of concurrent workers")
	flag.DurationVar(&cfg.Timeout, "t", 3*time.Second, "SSH connection timeout")
	flag.IntVar(&cfg.Port, "P", 22, "SSH port")
	flag.StringVar(&cfg.OutputFile, "o", "", "Output file for successful IPs")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <cidr> [user] [password]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s 192.168.1.0/24\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -u admin -p password -w 200 192.168.1.0/24\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s 3 root 123456  (Equivalent to: -u root -p 123456 192.168.3.0/24)\n", os.Args[0])
	}

	flag.Parse()

	switch flag.NArg() {
	case 1:
		cfg.CIDR = flag.Arg(0)
	case 3:
		cfg.CIDR = flag.Arg(0)
		cfg.User = flag.Arg(1)
		cfg.Password = flag.Arg(2)
	default:
		flag.Usage()
		os.Exit(1)
	}

	return cfg
}

func main() {
	cfg := parseConfig()

	ip, ipNet, err := parseInput(cfg.CIDR)
	if err != nil {
		fmt.Printf("%sInvalid CIDR or IP: %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}

	// Calculate total IPs
	ones, bits := ipNet.Mask.Size()
	totalIPs := uint64(1) << (bits - ones)
	if bits == 0 { // Handle non-standard masks or issues gracefully
		totalIPs = 0
	}

	// Use a channel for IPs to save memory on large ranges
	ips := generateIPs(ip, ipNet, cfg.Workers)

	fmt.Printf("%sScanning %s (%d IPs) with %d workers on port %d...%s\n",
		ColorCyan, cfg.CIDR, totalIPs, cfg.Workers, cfg.Port, ColorReset)

	scan(ips, cfg, totalIPs)
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

func generateIPs(ip net.IP, ipNet *net.IPNet, workers int) chan string {
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

func scan(ips chan string, cfg *Config, totalIPs uint64) {
	var (
		wg             sync.WaitGroup
		failNum, okNum atomic.Int32
		processedNum   atomic.Int32
		sem            = make(chan struct{}, cfg.Workers)
		outputMutex    sync.Mutex
		printMutex     sync.Mutex // Synchronize stdout
		f              *os.File
		err            error
	)

	if cfg.OutputFile != "" {
		f, err = os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Printf("%sFailed to create output file: %v%s\n", ColorRed, err, ColorReset)
			return
		}
		defer f.Close()
	}

	startTime := time.Now()

	// Helper to print progress bar
	printProgress := func() {
		current := processedNum.Load()
		percent := 0.0
		if totalIPs > 0 {
			percent = float64(current) / float64(totalIPs) * 100
		}
		fmt.Printf("\rProgress: %d/%d (%.1f%%) | Found: %s%d%s",
			current, totalIPs, percent, ColorGreen, okNum.Load(), ColorReset)
	}

	// Progress updater
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				printMutex.Lock()
				printProgress()
				printMutex.Unlock()
			case <-done:
				return
			}
		}
	}()

	for ip := range ips {
		wg.Add(1)
		sem <- struct{}{} // Acquire token
		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-sem }() // Release token

			addr := fmt.Sprintf("%s:%d", targetIP, cfg.Port)
			if err := tryConnectSSH(addr, cfg.User, cfg.Password, cfg.Timeout); err == nil {
				okNum.Add(1)

				// Critical section for printing
				printMutex.Lock()
				// Clear line to avoid messing up progress bar
				fmt.Printf("\r\033[K")
				fmt.Printf("%s[+] %s%s\n", ColorGreen, targetIP, ColorReset)
				// Immediately reprint progress bar to avoid flashing
				printProgress()
				printMutex.Unlock()

				if f != nil {
					outputMutex.Lock()
					f.WriteString(targetIP + "\n")
					outputMutex.Unlock()
				}
			} else {
				failNum.Add(1)
			}
			processedNum.Add(1)
		}(ip)
	}

	wg.Wait()
	close(done)

	duration := time.Since(startTime)
	rate := float64(processedNum.Load()) / duration.Seconds()

	// Final clear and summary
	printMutex.Lock()
	fmt.Printf("\r\033[K")
	fmt.Println("--------------------")
	fmt.Printf("Scan Complete in %s%v%s\n", ColorCyan, duration.Round(time.Millisecond), ColorReset)
	fmt.Printf("Rate: %s%.2f IPs/s%s\n", ColorCyan, rate, ColorReset)
	fmt.Printf("Results: %s%d Success%s, %s%d Failed%s\n",
		ColorGreen, okNum.Load(), ColorReset,
		ColorRed, failNum.Load(), ColorReset)
	printMutex.Unlock()
}

func tryConnectSSH(addr, user, password string, timeout time.Duration) error {
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
