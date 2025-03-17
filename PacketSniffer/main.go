package main

import (
	p "PacketSniffer/packet"
)

//const targetIP = "192.168.0.135"
// const targetIP = "8.8.8.8"

/*
different modes for sniff
API/api = sends to API (localhost:8080/IPv4Data)
File/file = sends to file in /PCAP_Files directory
empty string = prints to console
*/
func main() {
	device := p.GetDefaultInterface()
	targetIP := device.DeviceIP
	p.Sniff(targetIP, "API")
}
