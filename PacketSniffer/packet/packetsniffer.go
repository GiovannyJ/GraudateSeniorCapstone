package packet

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"regexp"
	"bytes"
	"runtime"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	a "PacketSniffer/API"
	f "PacketSniffer/file"
	h "PacketSniffer/helper"
	s "PacketSniffer/structs"
)


var (
	ipPacket    map[string]int
	maxPacketSize uint16 = 0
	minPacketSize uint16 = 65535 // Start with max value
)



func getDefaultInterface() *s.TargetDevice {
	// Get the default gateway
	var gateway net.IP
	var err error
	
	os := runtime.GOOS

	switch os {
	case "windows":
		gateway, err = getDefaultGatewayWindows()
	case "linux":
		gateway, err = getDefaultGatewayLinux()
	case "darwin":
		gateway, err = getDefaultGatewayMacOS()
	default:
		fmt.Printf("Running on an unsupported OS: %s\n", os)
	}

	if err != nil {
		h.Warn("Error getting default gateway: " + err.Error())
		return nil
	}

	// Get all network devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		h.Warn("Error finding network devices: " + err.Error())
		return nil
	}

	h.Okay("Available Interfaces:")
	for _, device := range devices {
		h.Info("Name: %s, Addresses: %v", device.Name, device.Addresses)
		for _, address := range device.Addresses {
			mask := net.IP(address.Netmask).String()
			h.Info("Checking device: %s, IP: %s, Mask: %s\n", device.Name, address.IP.String(), mask)

			// Check if the IP is in the same subnet as the default gateway
			if isInSameSubnet(net.ParseIP(address.IP.String()), gateway, net.IP(address.Netmask)) {
				h.Okay("Selected device: %s\n", device.Name)
				return &s.TargetDevice{DeviceName: device.Name, DeviceIP: address.IP.String()}
			}
		}
	}

	h.Warn("No suitable network interfaces found")
	return nil
}


// GetDefaultGateway extracts the default gateway from `route print 0.0.0.0`
func getDefaultGatewayWindows() (net.IP, error) {
	// Execute the Windows command to get the route info
	cmd := exec.Command("cmd", "/C", "route print 0.0.0.0")
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute command: %v", err)
	}

	// Convert output to string and split into lines
	output := out.String()
	lines := strings.Split(output, "\n")

	// Define regex pattern to match the default gateway IP
	re := regexp.MustCompile(`\s*0.0.0.0\s+0.0.0.0\s+(\d+\.\d+\.\d+\.\d+)`)

	// Iterate through lines to find the match
	for _, line := range lines {
		match := re.FindStringSubmatch(line)
		if len(match) > 1 {
			return net.ParseIP(match[1]), nil // Convert string to net.IP
		}
	}

	return nil, fmt.Errorf("default gateway not found")
}


// getDefaultGateway returns the IP address of the default gateway
func getDefaultGatewayLinux() (net.IP, error) {
	// Use system commands or a library to get the default gateway
	// For simplicity, this example assumes a Linux system
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil, err
	}

	// Parse the output to extract the gateway IP
	fields := strings.Fields(string(out))
	if len(fields) < 3 {
		return nil, fmt.Errorf("unexpected output from 'ip route'")
	}

	return net.ParseIP(fields[2]), nil
}

func getDefaultGatewayMacOS() (net.IP, error) {
	out, err := exec.Command("netstat", "-rn").Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(out), "\n")
	re := regexp.MustCompile(`default\s+(\d+\.\d+\.\d+\.\d+)`)

	for _, line := range lines {
		match := re.FindStringSubmatch(line)
		if len(match) > 1 {
			return net.ParseIP(match[1]), nil
		}
	}

	return nil, fmt.Errorf("default gateway not found")
}

// isInSameSubnet checks if two IPs are in the same subnet
func isInSameSubnet(ip1, ip2, mask net.IP) bool {
	ip1Masked := ip1.Mask(net.IPMask(mask))
	ip2Masked := ip2.Mask(net.IPMask(mask))
	return ip1Masked.Equal(ip2Masked)
}







func ipv4PacketScan(packet gopacket.Packet, sourceIP string, targetIP string) *s.PacketScanResults {
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer != nil {
		ip, _ := ip4Layer.(*layers.IPv4)

		// Skip packets not between the two IPs
		if !((ip.SrcIP.String() == sourceIP && ip.DstIP.String() == targetIP) || (ip.SrcIP.String() == targetIP && ip.DstIP.String() == sourceIP)) {
			return nil
		}

		// Ensure ipPacket map is initialized
		if ipPacket == nil {
			ipPacket = make(map[string]int)
		}

		// Update packet count for source IP
		ipPacket[ip.SrcIP.String()]++

		// Initialize minPacketSize if needed
		if minPacketSize == 0 || ip.Length < minPacketSize {
			minPacketSize = ip.Length
		}

		// Track max packet size
		if ip.Length > maxPacketSize {
			maxPacketSize = ip.Length
		}

		// Create IPv4 scan result
		IPV4Results := s.NewIPv4ScanResults(ip, h.CleanPayload(ip.Payload))
		

		// TCP Scan Results
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			TCPResults := s.NewTCPScanResults(ip, tcp)
			return s.NewPacketScanResults(&IPV4Results, &TCPResults)
		}


		// Create and return PacketScanResults
	}
	return nil
}





func Sniff(targetIP string, mode string) {
	device := getDefaultInterface()
	h.Okay("Using network interface: %s\n", device)

	handle, err := pcap.OpenLive(device.DeviceName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// err = handle.SetBPFFilter("tcp and host" + targetIP)
	// if err != nil{
	// 	h.Warn("error")
	// }

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	h.Info("Starting packet scan")
	for packet := range packetSource.Packets() {
		scanResult := ipv4PacketScan(packet, device.DeviceIP, targetIP)
		// err = handle.WritePacketData(packet.Metadata().CaptureInfo.Data, packet.Metadata().CaptureInfo.Length)

		if scanResult != nil{
			if mode == "API" || mode == "api"{
				a.SendToAPI(*scanResult)
			}else if mode == "file" || mode == "File"{
				f.SendToFile(*scanResult)
				defer f.CloseFile()
			}else{
				fmt.Println(scanResult.ToJSON())
			}
			
		}
	}
}
