package file

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
	h "PacketSniffer/helper"
	s "PacketSniffer/structs"
)

var (
	sessionFile     *os.File // Global variable to hold the file reference
	sessionFileName string   // Global variable to hold the filename
	fileOnce        sync.Once // Ensures the file is opened only once
	firstWrite      = true   // Track if it's the first write to the file
)

// CreateFileWithTimestamp creates the file with a timestamped filename for the session
func CreateFileWithTimestamp() (*os.File, error) {
	var err error
	fileOnce.Do(func() {
		// Define the directory and generate a timestamped file name
		dir := "../PCAP_Files" // Directory path
		timestamp := time.Now().Format("2006-01-02_15-04-05")
		sessionFileName = fmt.Sprintf("%s/session_data_%s.json", dir, timestamp)

		// Open the file in append mode (create if it doesn't exist)
		sessionFile, err = os.OpenFile(sessionFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			h.Warn("Error opening file: %v", err)
			return
		}

		// Write the opening bracket for the JSON array
		_, err = sessionFile.Write([]byte("[\n"))
		if err != nil {
			h.Warn("Error writing opening bracket to file: %v", err)
			return
		}
	})

	return sessionFile, err
}

// SendToFile appends the IPv4ScanResult to the same file (opened in append mode)
func SendToFile(result s.IPv4ScanResults) error {
	// Ensure the file is opened (first call will create/open the file)
	if sessionFile == nil {
		// Create the file with a timestamp if it's not opened yet
		_, err := CreateFileWithTimestamp()
		if err != nil {
			return err
		}
	}

	// Serialize the IPv4ScanResults struct into JSON
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		h.Warn("Error serializing data: %v", err)
		return err
	}

	// Add a comma before the JSON object if it's not the first write
	if !firstWrite {
		_, err = sessionFile.Write([]byte(",\n"))
		if err != nil {
			h.Warn("Error writing comma to file: %v", err)
			return err
		}
	} else {
		firstWrite = false
	}

	// Write the JSON data to the file
	_, err = sessionFile.Write(jsonData)
	if err != nil {
		h.Warn("Error writing to file: %v", err)
		return err
	}

	// Print success message
	h.Okay("Data written successfully to the session file.")

	return nil
}

// CloseFile closes the file and writes the closing bracket for the JSON array
func CloseFile() error {
	if sessionFile != nil {
		// Write the closing bracket for the JSON array
		_, err := sessionFile.Write([]byte("\n]"))
		if err != nil {
			h.Warn("Error writing closing bracket to file: %v", err)
			return err
		}

		// Close the file
		err = sessionFile.Close()
		if err != nil {
			h.Warn("Error closing file: %v", err)
			return err
		}

		h.Okay("Session file closed successfully.")
	}
	return nil
}
