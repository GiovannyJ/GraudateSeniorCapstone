package main

import (
	"crypto/rand"
	"crypto/rsa"
	// "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	h "MalPacket/helper"
)

func main() {
	// Open the network interface for packet sending
	device := h.GetDefaultInterface()
	h.Okay("Using network interface: %s\n", device)

	handle, err := pcap.OpenLive(device.DeviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", device, err)
	}
	defer handle.Close()

	// Generate a legitimate certificate and a fake certificate
	// legitCert, legitKey := generateCertificate(true)
	// fakeCert, fakeKey := generateCertificate(false)

	// Simulate sending packets
	for i := 0; i < 10; i++ {
		var payload []byte
		// var cert tls.Certificate

		// Alternate between legitimate and malicious payloads
		if i%2 == 0 {
			payload = []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") // Legitimate payload
			// cert = tls.Certificate{
			// 	Certificate: [][]byte{legitCert.Raw},
			// 	PrivateKey:  legitKey,
			// }
		} else {
			payload = []byte("eval('malicious code')") // Malicious payload
			// cert = tls.Certificate{
			// 	Certificate: [][]byte{fakeCert.Raw},
			// 	PrivateKey:  fakeKey,
			// }
		}

		// Simulate an encrypted payload (random data)
		encryptedPayload := simulateEncryptedPayload(payload)

		// Send the packet
		sendTCPPacket(handle, "192.168.0.135", "192.168.0.135", 489, 80, encryptedPayload)

		log.Printf("Packet %d sent (Malicious: %v)\n", i+1, i%2 != 0)
		time.Sleep(100 * time.Millisecond) // Simulate realistic timing
	}
}

// Generate a certificate (legitimate or fake)
func generateCertificate(legit bool) (*x509.Certificate, *rsa.PrivateKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Example Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	if !legit {
		template.Subject.Organization = []string{"Fake Org"} // Fake certificate
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		log.Fatalf("Error creating certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Fatalf("Error parsing certificate: %v", err)
	}

	return cert, privKey
}

// Simulate an encrypted payload
func simulateEncryptedPayload(payload []byte) []byte {
	// Generate random data to simulate encryption
	encryptedPayload := make([]byte, len(payload))
	_, err := rand.Read(encryptedPayload)
	if err != nil {
		log.Fatalf("Error generating random payload: %v", err)
	}
	return encryptedPayload
}

// Send a TCP packet
func sendTCPPacket(handle *pcap.Handle, srcIP, dstIP string, srcPort, dstPort int, payload []byte) {
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
		SrcIP:    net.ParseIP(srcIP).To4(), // Source IP
		DstIP:    net.ParseIP(dstIP).To4(), // Destination IP
		Protocol: layers.IPProtocolTCP,
	}

	// Create the TCP layer
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort), // Source port
		DstPort: layers.TCPPort(dstPort), // Destination port
		SYN:     false,                   // No SYN flag for data packets
	}
	tcp.SetNetworkLayerForChecksum(ip)

	// Serialize the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))
	if err != nil {
		log.Fatalf("Error serializing packet: %v", err)
	}

	// Send the packet
	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		log.Fatalf("Error sending packet: %v", err)
	}
}