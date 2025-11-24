package main

import (
	"net"
	"reflect"
	"testing"
)

func TestGenerateIPs(t *testing.T) {
	tests := []struct {
		cidr     string
		expected []string
	}{
		{
			cidr: "192.168.1.0/30",
			// 192.168.1.0 (network) - skipped
			// 192.168.1.1
			// 192.168.1.2
			// 192.168.1.3 (broadcast) - skipped
			expected: []string{"192.168.1.1", "192.168.1.2"},
		},
		{
			cidr: "10.0.0.1/32",
			// Single IP
			expected: []string{"10.0.0.1"},
		},
	}

	for _, tt := range tests {
		ip, ipNet, err := net.ParseCIDR(tt.cidr)
		if err != nil {
			t.Fatalf("Failed to parse CIDR %s: %v", tt.cidr, err)
		}

		got := generateIPs(ip, ipNet)
		if !reflect.DeepEqual(got, tt.expected) {
			t.Errorf("generateIPs(%s) = %v, want %v", tt.cidr, got, tt.expected)
		}
	}
}

func TestParseInput(t *testing.T) {
	tests := []struct {
		input    string
		wantErr  bool
		expected string // CIDR string representation of the network
	}{
		{
			input:    "192.168.1.0/24",
			wantErr:  false,
			expected: "192.168.1.0/24",
		},
		{
			input:    "10.0.0.1",
			wantErr:  false,
			expected: "10.0.0.1/32",
		},
		{
			input:    "3",
			wantErr:  false,
			expected: "192.168.3.0/24",
		},
		{
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		_, ipNet, err := parseInput(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseInput(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr {
			if ipNet.String() != tt.expected {
				t.Errorf("parseInput(%s) = %v, want %v", tt.input, ipNet.String(), tt.expected)
			}
		}
	}
}

