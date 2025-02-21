package helper

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TargetDevice struct {
	DeviceName string `json:"devicename"`
	DeviceIP   string `json:"deviceip"`
}

func Okay(message string, args ...interface{}){fmt.Printf("[+] " + message+"\n", args...)}
func Info(message string, args ...interface{}){fmt.Printf("[i] " + message+"\n", args...)}
func Warn(message string, args ...interface{}){fmt.Printf("[!] " + message+"\n", args...)}


func GetDefaultInterface() *TargetDevice {
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
		Warn("Error getting default gateway: " + err.Error())
		return nil
	}

	// Get all network devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		Warn("Error finding network devices: " + err.Error())
		return nil
	}

	Okay("Available Interfaces:")
	for _, device := range devices {
		Info("Name: %s, Addresses: %v", device.Name, device.Addresses)
		for _, address := range device.Addresses {
			mask := net.IP(address.Netmask).String()
			Info("Checking device: %s, IP: %s, Mask: %s\n", device.Name, address.IP.String(), mask)

			// Check if the IP is in the same subnet as the default gateway
			if isInSameSubnet(net.ParseIP(address.IP.String()), gateway, net.IP(address.Netmask)) {
				Okay("Selected device: %s\n", device.Name)
				return &TargetDevice{DeviceName: device.Name, DeviceIP: address.IP.String()}
			}
		}
	}

	Warn("No suitable network interfaces found")
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

// func SendTCPPacket(handle *pcap.Handle, srcIP, dstIP string, srcPort, dstPort int, payload []byte) {
// 	eth := &layers.Ethernet{
// 		SrcMAC:       net.HardwareAddr{0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF},
// 		DstMAC:       net.HardwareAddr{0x00, 0x0C, 0x29, 0x12, 0x34, 0x56},
// 		EthernetType: layers.EthernetTypeIPv4,
// 	}

// 	ip := &layers.IPv4{
// 		Version:  4,
// 		TTL:      64,
// 		SrcIP:    net.ParseIP(srcIP).To4(),
// 		DstIP:    net.ParseIP(dstIP).To4(),
// 		Protocol: layers.IPProtocolTCP,
// 	}

// 	tcp := &layers.TCP{
// 		SrcPort: layers.TCPPort(srcPort),
// 		DstPort: layers.TCPPort(dstPort),
// 		SYN:     true,
// 	}
// 	tcp.SetNetworkLayerForChecksum(ip)

// 	buf := gopacket.NewSerializeBuffer()
// 	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
// 	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
// 		Warn("Error serializing packet: %v", err)
// 	}

// 	if err := handle.WritePacketData(buf.Bytes()); err != nil {
// 		Warn("Error sending packet: %v", err)
// 	}
// 	Okay("Packet sent")
// }

func SendTCPPacket(handle *pcap.Handle, srcIP, dstIP string, srcPort, dstPort int, payload []byte) error {
    // Parse IP addresses
    srcIPAddr := net.ParseIP(srcIP).To4()
    dstIPAddr := net.ParseIP(dstIP).To4()
    if srcIPAddr == nil || dstIPAddr == nil {
        Warn("Invalid IP address")
    }

    // Create Ethernet layer
    eth := &layers.Ethernet{
        SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Replace with your source MAC
        DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Replace with your destination MAC
        EthernetType: layers.EthernetTypeIPv4,
    }

    // Create IP layer
    ip := &layers.IPv4{
        SrcIP:    srcIPAddr,
        DstIP:    dstIPAddr,
        Version:  4,
        TTL:      64,
        Protocol: layers.IPProtocolTCP,
    }

    // Create TCP layer
    tcp := &layers.TCP{
        SrcPort: layers.TCPPort(srcPort),
        DstPort: layers.TCPPort(dstPort),
        Seq:     1105024978, // Random sequence number
        SYN:     true,       // Set SYN flag (or other flags as needed)
        Window:  14600,      // Default window size
    }

    // Set TCP checksum
    err := tcp.SetNetworkLayerForChecksum(ip)
    if err != nil {
        return err
    }

    // Serialize the packet
    buffer := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{
        FixLengths:       true,
        ComputeChecksums: true,
    }
    err = gopacket.SerializeLayers(buffer, opts, eth, ip, tcp, gopacket.Payload(payload))
    if err != nil {
        return err
    }

    // Send the packet
    err = handle.WritePacketData(buffer.Bytes())
    if err != nil {
        return err
    }

    return nil
}