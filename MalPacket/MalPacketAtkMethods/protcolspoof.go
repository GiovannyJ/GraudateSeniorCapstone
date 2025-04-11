package malpacketatkmethods

import (
	"net"
	
	h "MalPacket/helper"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
)
/*
simulating TCP from a faked location
*/
func GenerateSpoofPacket(handle *pcap.Handle, srcIP, dstIP string, srcPort, dstPort int, payload []byte) {
	// Parse IP addresses
	srcIPAddr := net.ParseIP(srcIP).To4()
	dstIPAddr := net.ParseIP(dstIP).To4()
	if srcIPAddr == nil || dstIPAddr == nil {
		h.Warn("Invalid IP address")
	}

	// Create Ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Replace with your source MAC
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Replace with your destination MAC
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIPAddr,
		DstIP:    dstIPAddr,
		// Protocol: layers.IPProtocolICMPv4, // Spoof the protocol to ICMP
		Protocol: layers.IPProtocolTCP,
	}
	
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(GenerateRandomPort()),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte{})); err != nil {
		h.Warn("Error serializing packet: %v", err)
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		h.Warn("Error sending packet: %v", err)
	}

}