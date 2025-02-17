package structs

import (
	"github.com/google/gopacket/layers"
	"fmt"
	"encoding/json"
	"time"
)

type TargetDevice struct {
	DeviceName string `json:"devicename"`
	DeviceIP   string `json:"deviceip"`
}



type IPv4ScanResults struct {
	Type        string            `json:"type"`
	Source      string            `json:"source"`
	Destination string            `json:"destination"`
	Protocol    string            `json:"protocol"`
	Flags       []string          `json:"flags"`
	FragOffset  int               `json:"frag_offset"`
	IHL         int               `json:"ihl"`
	Length      int               `json:"length"`
	Options     []layers.IPv4Option `json:"options"`
	Padding     []byte            `json:"padding"`
	BaseLayer   layers.BaseLayer  `json:"base_layer"`
	Checksum    uint16            `json:"checksum"`
	TimeToLive  uint8             `json:"ttl"`
	Version     uint8             `json:"version"`
	TOS         uint8             `json:"tos"`
	Payload     string            `json:"payload"`
	TimeStamp	time.Time		  `json:"timestamp"`
}

func NewIPv4ScanResults(ip *layers.IPv4, payload string) IPv4ScanResults {
	return IPv4ScanResults{
		Type:        ip.LayerType().String(),
		Source:      ip.SrcIP.String(),
		Destination: ip.DstIP.String(),
		Protocol:    ip.Protocol.String(),
		Flags:       ipv4FlagsToSlice(ip.Flags),
		FragOffset:  int(ip.FragOffset),
		IHL:         int(ip.IHL),
		Length:      int(ip.Length),
		Options:     ip.Options,
		Padding:     ip.Padding,
		BaseLayer:   ip.BaseLayer,
		Checksum:    ip.Checksum,
		TimeToLive:  ip.TTL,
		Version:     ip.Version,
		TOS:         ip.TOS,
		Payload:     payload,
		TimeStamp: time.Now(),
	}
}

func ipv4FlagsToSlice(flags layers.IPv4Flag) []string {
	var flagList []string
	if flags&layers.IPv4DontFragment != 0 {
		flagList = append(flagList, "DontFragment")
	}
	if flags&layers.IPv4MoreFragments != 0 {
		flagList = append(flagList, "MoreFragments")
	}
	return flagList
}

func (r IPv4ScanResults) ToJSON() string {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}

// Print IPv4 scan results in a readable format
func (r IPv4ScanResults) PrintScanResults() {
	fmt.Println("=================================PACKET==================================")
	fmt.Printf("From %s, To %s\n", r.Source, r.Destination)
	fmt.Println("Protocol:", r.Protocol)
	fmt.Println("Flags:", r.Flags)
	fmt.Println("Fragment Offset:", r.FragOffset)
	fmt.Println("IHL:", r.IHL)
	fmt.Println("Packet Length:", r.Length)
	fmt.Println("Options:", r.Options)
	fmt.Println("Checksum:", r.Checksum)
	fmt.Println("TTL:", r.TimeToLive)
	fmt.Println("Version:", r.Version)
	fmt.Println("TOS:", r.TOS)
	fmt.Println("Payload:", r.Payload)
	fmt.Println("#########################################################################")
}


type TCPScanResults struct {
	SourceIP           string `json:"source_ip"`
	DestinationIP      string `json:"destination_ip"`
	SourcePort         string `json:"source_port"`
	DestinationPort    string `json:"destination_port"`
	SequenceNumber     uint32 `json:"sequence_number"`
	AcknowledgmentNum  uint32 `json:"acknowledgment_number"`
	DataOffset         uint8  `json:"data_offset"`
	Flags              string `json:"flags"`
	WindowSize         uint16 `json:"window_size"`
	Checksum           uint16 `json:"checksum"`
	UrgentPointer      uint16 `json:"urgent_pointer"`
	Payload            string `json:"payload"`
	PayloadHex         string `json:"payload_hex"`
	TimeStamp	time.Time		  `json:"timestamp"`

}
func NewTCPScanResults(ip *layers.IPv4, tcp *layers.TCP) TCPScanResults {
	// Format flags as a string
	flags := fmt.Sprintf("FIN:%t SYN:%t RST:%t PSH:%t ACK:%t URG:%t ECE:%t CWR:%t NS:%t",
		tcp.FIN, tcp.SYN, tcp.RST, tcp.PSH, tcp.ACK, tcp.URG, tcp.ECE, tcp.CWR, tcp.NS)

	// Create the TCPScanResults
	return TCPScanResults{
		SourceIP:           ip.SrcIP.String(),
		DestinationIP:      ip.DstIP.String(),
		SourcePort:         tcp.SrcPort.String(),
		DestinationPort:    tcp.DstPort.String(),
		SequenceNumber:     tcp.Seq,
		AcknowledgmentNum:  tcp.Ack,
		DataOffset:         tcp.DataOffset,
		Flags:              flags,
		WindowSize:         tcp.Window,
		Checksum:           tcp.Checksum,
		UrgentPointer:      tcp.Urgent,
		Payload:            string(tcp.Payload), // Payload as string
		PayloadHex:         fmt.Sprintf("%x", tcp.Payload), // Payload as hex
		TimeStamp: 			time.Now(),
	}
}

func (r TCPScanResults) ToJSON() string {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}


type PacketScanResults struct {
	IPv4Data *IPv4ScanResults `json:"ipv4data"`
	TCPData  *TCPScanResults  `json:"tcpdata"`
}

func NewPacketScanResults(i *IPv4ScanResults, t *TCPScanResults) *PacketScanResults {
	return &PacketScanResults{
		IPv4Data: i,
		TCPData:  t,
	}
}

func (r PacketScanResults) ToJSON() string {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}