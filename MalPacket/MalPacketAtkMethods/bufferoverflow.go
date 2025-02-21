package malpacketatkmethods

import (
	h "MalPacket/helper"
	

	"github.com/google/gopacket/pcap"
)


/*
A payload of a large size may indicate that there is a buffer overflow attack in progress
1460 is the biggest size we can send before it crashes
*/
func GenerateBufferOverFlowPacket(handle *pcap.Handle, srcIP, dstIP string, srcPort ,dstPort int){
	payload := make([]byte, 1460)
	for i:= range payload{
		payload[i] = 0x90
	}
	
	err := h.SendTCPPacket(handle, srcIP, dstIP, srcPort, dstPort, payload)
	if err != nil{
		h.Warn("Error sending packets: %v", err)
	}
}