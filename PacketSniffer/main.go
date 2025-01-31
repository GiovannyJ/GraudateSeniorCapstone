package packetsniffer

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Open the device for capturing
	//! make modular for different devices
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter string = "tcp"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	// Use the handle as a packet source to process all packets
	//! make so it goes to specified host
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		// Check for the TCP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			//! pack and send to API

			// Print TCP information
			log.Printf("From src port: %d to dst port: %d\n", tcp.SrcPort, tcp.DstPort)
			log.Printf("Sequence number: %d\n", tcp.Seq)

			// If there's payload, print it as a string
			if len(tcp.Payload) > 0 {
				log.Printf("Payload: %s\n", string(tcp.Payload))
			}
		}
	}
}