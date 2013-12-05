package main

import (
	"bufio"
	"errors"
	"net"
	"os"
)

// Builds a slice of IP addresses from a file containing
// IP and networks.
func buildScope(file string) ([]string, error) {
	scope := []string{}
	f, err := os.Open(file)
	if err != nil {
		return scope, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		scope = append(scope, scanner.Text())
	}
	if scanner.Err() != nil {
		return scope, scanner.Err()
	}
	return linesToIpList(scope)
}

// Processes a list of IP addresses or networks in CIDR format.
// Returning a list of all possible IP addresses.
func linesToIpList(lines []string) ([]string, error) {
	ipList := []string{}
	for _, line := range lines {
		if net.ParseIP(line) != nil {
			ipList = append(ipList, line)
		} else if ip, network, err := net.ParseCIDR(line); err == nil {
			for ip := ip.Mask(network.Mask); network.Contains(ip); increaseIp(ip) {
				ipList = append(ipList, ip.String())
			}
		} else {
			return ipList, errors.New("\"" + line + "\" is not an IP Address or CIDR Network")
		}
	}
	return ipList, nil
}

// Increases an IP by a single address.
func increaseIp(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
