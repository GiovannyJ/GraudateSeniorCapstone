package main

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Open the network interface for packet sending
	device := "eth0" // Change this to your network interface
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", device, err)
	}
	defer handle.Close()

	// Create the Ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF}, // Source MAC
		DstMAC:       net.HardwareAddr{0x00, 0x0C, 0x29, 0x12, 0x34, 0x56}, // Destination MAC
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create the IPv4 layer
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 1, 100}, // Source IP
		DstIP:    net.IP{192, 168, 1, 1},   // Destination IP
		Protocol: layers.IPProtocolTCP,
	}

	// Create the TCP layer
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(12345), // Source port
		DstPort: layers.TCPPort(80),    // Destination port (HTTP)
		SYN:     true,                  // Set SYN flag
	}
	tcp.SetNetworkLayerForChecksum(ip)

	// Create the malicious payload
	payload := []byte("eval('malicious code')")

	// Serialize the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))
	if err != nil {
		log.Fatalf("Error serializing packet: %v", err)
	}

	// Send the packet
	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		log.Fatalf("Error sending packet: %v", err)
	}

	log.Println("Malicious packet sent!")
}