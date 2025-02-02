package main

import (
	p "PacketSniffer/packet"
)

const targetIP = "8.8.8.8"


func main() {
	p.Sniff(targetIP)
}