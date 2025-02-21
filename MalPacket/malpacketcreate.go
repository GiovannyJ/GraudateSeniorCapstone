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

func main() {
	
	device := h.GetDefaultInterface()
	h.Okay("Using network interface: %s\n", device.DeviceName)

	handle, err := pcap.OpenLive(device.DeviceName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", device.DeviceName, err)
	}
	defer handle.Close()

	// Simulate sending packets
	
	for i := 0; i < 1000; i++ {
		// r := rand.Intn(100) // Generate a random number between 0 and 99
	
		// switch {
		// case r < 15:
		// 	a.GenerateSYNFlood(handle, targetIP, targetIP, 489, 800)
		// 	h.Okay("SYN Packet Sent")
	
		// case r <25: 
		// 	a.GenerateBufferOverFlowPacket(handle, targetIP, targetIP, 489, 80)
		// 	h.Okay("Buffer Overflow Packet Sent")
	
		// default:
			// payload := generateHTTPPayload()
			// encryptedPayload := simulateEncryptedPayload(payload)
			// h.SendTCPPacket(handle, targetIP, targetIP, 489, 80, encryptedPayload)
			// h.Okay("Normal Packet Sent")
		// }

		payload := generateHTTPPayload()
		a.GenerateSpoofPacket(handle, targetIP, targetIP, 443, 443, payload)
		h.Okay("Spoof Packet Sent")
		
	
		time.Sleep(100 * time.Millisecond)
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



