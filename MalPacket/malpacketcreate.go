package main

import (
<<<<<<< Updated upstream
	"log"
=======
	// "crypto/rand"
	"fmt"
	"log"
	"math/rand"
>>>>>>> Stashed changes
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Open the network interface for packet sending
<<<<<<< Updated upstream
	device := "eth0" // Change this to your network interface
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
=======
	device := h.GetDefaultInterface()
	h.Okay("Using network interface: %s\n", device.DeviceName)

	handle, err := pcap.OpenLive(device.DeviceName, 1600, true, pcap.BlockForever)
>>>>>>> Stashed changes
	if err != nil {
		log.Fatalf("Error opening device %s: %v", device.DeviceName, err)
	}
	defer handle.Close()

<<<<<<< Updated upstream
	// Create the Ethernet layer
=======
	// Simulate sending packets
	for i := 0; i < 20; i++ {
		var payload []byte

		payload = generateHTTPPayload()
		// if i%2 == 0 {
		// } else {
		// 	payload = generateMaliciousPayload()
		// }

		encryptedPayload := simulateEncryptedPayload(payload)

		sendTCPPacket(handle, "192.168.0.135", "192.168.0.135", 489, 80, encryptedPayload)

		log.Printf("Packet %d sent (Malicious: %v)\n", i+1, i%2 != 0)
		time.Sleep(100 * time.Millisecond)
	}
}

func generateHTTPPayload() []byte {
	paths := []string{"/", "/index.html", "/about", "/contact", "/products"}
	randomPath := paths[rand.Intn(len(paths))]
	return []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", randomPath))
}

func generateMaliciousPayload() []byte {
	maliciousPayloads := []string{
		"'; DROP TABLE users; --",
		"<script>alert('XSS')</script>",
		"../../../../etc/passwd",
		"OR 1=1; --",
	}
	randomIndex := rand.Intn(len(maliciousPayloads))
	return []byte(maliciousPayloads[randomIndex])
}

func simulateEncryptedPayload(payload []byte) []byte {
	encryptedPayload := make([]byte, len(payload))
	_, err := rand.Read(encryptedPayload)
	if err != nil {
		log.Fatalf("Error generating random payload: %v", err)
	}
	return encryptedPayload
}

func sendTCPPacket(handle *pcap.Handle, srcIP, dstIP string, srcPort, dstPort int, payload []byte) {
>>>>>>> Stashed changes
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF},
		DstMAC:       net.HardwareAddr{0x00, 0x0C, 0x29, 0x12, 0x34, 0x56},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
<<<<<<< Updated upstream
		SrcIP:    net.IP{192, 168, 1, 100}, // Source IP
		DstIP:    net.IP{192, 168, 1, 1},   // Destination IP
=======
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
>>>>>>> Stashed changes
		Protocol: layers.IPProtocolTCP,
	}

	tcp := &layers.TCP{
<<<<<<< Updated upstream
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
=======
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
>>>>>>> Stashed changes
		log.Fatalf("Error serializing packet: %v", err)
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		log.Fatalf("Error sending packet: %v", err)
	}
<<<<<<< Updated upstream

	log.Println("Malicious packet sent!")
}
=======
}
>>>>>>> Stashed changes
