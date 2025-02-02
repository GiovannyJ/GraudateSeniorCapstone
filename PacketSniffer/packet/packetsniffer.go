package packet

import (
	"log"
	"net"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	
	h "PacketSniffer/helper"
	s "PacketSniffer/structs"
)


var (
	ipPacket    map[string]int
	maxPacketSize uint16 = 0
	minPacketSize uint16 = 65535 // Start with max valu
)



func getDefaultInterface() *s.TargetDevice {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Error finding network devices:", err)
	}

	log.Println("Available Interfaces:")
	for _, device := range devices {
		log.Printf("Name: %s, Addresses: %v\n", device.Name, device.Addresses)
		for _, address := range device.Addresses{
			mask := net.IP(address.Netmask).String()
			log.Printf("Checking device: %s, IP: %s, Mask: %s\n", device.Name, address.IP.String(), mask)

			// Match subnet mask 255.255.255.0
			if mask == "255.255.255.0" {
				log.Printf("Selected device: %s\n", device.Name)
				return &s.TargetDevice{DeviceName: device.Name, DeviceIP: address.IP.String()}
			}
		}
	}

	log.Fatal("No network interfaces found")
	return nil
}




func ipv4PacketScan(packet gopacket.Packet, source_ip string, targetIP string) {
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer != nil {
		ip, _ := ip4Layer.(*layers.IPv4)

		if !((ip.SrcIP.String() == source_ip && ip.DstIP.String() == targetIP) || (ip.SrcIP.String() == targetIP && ip.DstIP.String() == source_ip)) {
			return // Skip packet if not between the two IPs
		}

		// Ensure ipPacket map is initialized before assigning values
		if ipPacket == nil {
			ipPacket = make(map[string]int)
		}		

		// Update packet count for source IP
		if value, ok := ipPacket[ip.SrcIP.String()]; !ok {
			ipPacket[ip.SrcIP.String()] = 1
		} else {
			ipPacket[ip.SrcIP.String()] = value + 1
		}

		// Track max and min packet size
		if ip.Length > maxPacketSize {
			maxPacketSize = ip.Length
		}
		if ip.Length < minPacketSize {
			minPacketSize = ip.Length
		}
		
		// Print IPv4 details
		results := s.NewIPv4ScanResults(ip, h.CleanPayload(ip.Payload))
		
		fmt.Println(results.ToJSON())
	}
}




func Sniff(targetIP string) {
	device := getDefaultInterface()
	log.Printf("Using network interface: %s\n", device)

	handle, err := pcap.OpenLive(device.DeviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println("=================================PACKET==================================")
		ipv4PacketScan(packet, device.DeviceIP, targetIP)
	}
}
