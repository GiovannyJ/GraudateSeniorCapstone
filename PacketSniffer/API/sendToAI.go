package api

import (
	"bytes"
	"encoding/json"
	"net/http"

	s "PacketSniffer/structs"
	h "PacketSniffer/helper"
)



func SendToAPI(data s.PacketScanResults) {
	// Convert the struct to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		h.Warn("Error marshalling data: %v", err)
	}

	// Send the POST request to FastAPI
	resp, err := http.Post("http://localhost:8080/IPv4Data", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		h.Warn("Error sending request: %v", err)
	}
	defer resp.Body.Close()

	// Print the response status
	h.Okay("Response status:", resp.Status)
}
