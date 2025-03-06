# Cybersecurity Packet Sniffer & AI Model Integration  

## **Created By:** Angel and Giovanny  

This project consists of a **network packet sniffer**, an **AI model**, and a **web server** to display captured data in real-time. It allows packets to be sent to an API or saved to a file for further analysis.  

---

## **📂 Project Structure**  

### **Cyber/**  
- **`datasets/`** - Contains datasets for AI training.  
- **`AI_model.py`** - The AI route model for processing captured network data.  
- **`API.py`** - A test instance of how an API can be used to retrieve information from the network packet scanner.  
  - **POST Route:** `localhost:8080/IPv4Data`  
  - **Data Format:**  
    ```json
    {
      "type": "IPv4",
      "source": "192.168.0.135",
      "destination": "8.8.8.8",
      "protocol": "ICMPv4",
      "flags": null,
      "frag_offset": 0,
      "ihl": 5,
      "length": 84,
      "options": null,
      "padding": null,
      "base_layer": {
        "Contents": "RQAAVK/VAABAAQAAwKgAhwgICAg=",
        "Payload": "CADxQ7UoAAfrvZ5nAAAA..."
      },
      "checksum": 0,
      "ttl": 64,
      "version": 4,
      "tos": 0,
      "payload": "..ñCµ(..ë½.g....û.\r..."
    }
    ```

---

### **PacketSniffer/**  
#### **API/**  
- **`sendToAI.go`** - Sends `IPv4ScanResults` to the API (`http://localhost:8080/IPv4Data`) via a **POST request**.  

#### **file/**  
- **`filehandler.go`** - Writes `IPv4ScanResults` to a JSON file (`session_data_DATE_TIME.json`).  
  - **Known Issue:** The JSON file is missing a closing `]`. This will be fixed in future versions.  

#### **helper/**  
- **`helper.go`** - Contains functions for:  
  - Cleaning payloads from IPv4 packets (converting to readable Unicode).  
  - Console print macros for better readability.  

#### **packet/**  
- **`packetsniffer.go`** - The **core** of the packet sniffer:  
  - **Process:**  
    1. Gather OS-specific network gateway interface.  
    2. Open a **live handle** to monitor packets on this interface.  
    3. Iterate through packets in real-time.  
    4. Determine mode of operation:  
       - **API mode** → Send to `http://localhost:8080/IPv4Data`.  
       - **File mode** → Save packets in a session JSON file.  
       - **Console mode** → Print packets in the terminal.  

#### **structs/**  
- **`structs.go`** - Defines the data structures used in packet processing.  

#### **Main Entry Point**  
- **`main.go`** - The entry point of the packet sniffer.  
  - Allows the user to **select a run mode** (API/File/Console).  

---

### **PCAP_Files/**  
- Stores **packet capture files** in JSON format.  

---

## **🌐 WebServer/**  
This component runs a Django-based **web API** and serves a **live web page** for packet analysis.  

### **myapp/** (Main Web Application)  
#### **templates/**  
- **`display_data.html`** - The web page displaying IPv4 data via AJAX (auto-refresh every **1 second**).  

#### **Backend Logic**  
- **`urls.py`** - Defines the web server’s routes:  
  - **`''` (default route)** → Displays `display_data.html`.  
  - **`/IPv4Data`** → Handles **POST requests** (packet data API).  

- **`views.py`** - Handles logic for API & webpage updates:  
  - **`ipv4_data(request)`**  
    - Accepts data from `localhost:8080/IPv4Data`.  
    - Stores packets in a **global list (`live_data`)** for real-time display.  
  - **`display_data(request)`**  
    - Renders `display_data.html` with the **latest** stored packets.  

#### **Django Configuration**  
- **`settings.py`**  
  - The only modification: **Added `myapp`** to `INSTALLED_APPS`.  

- **`WebServer/urls.py`**  
  - Includes routes from the `myapp` directory.  

- **`manage.py`**  
  - The main entry point to start the Django web server.  

---

## **🚀 How to Run the Project**  

### **1️⃣ Running the Web Server**  
```bash
pip install -r requirements.txt
cd WebServer
python manage.py runserver 8080
```
### **2️⃣Selecting a Target & Mode**
- **Set Target IP:** Modify the targetIP variable in main.go
- **Select mode:** Modify the second argument of p.Sniff()
    - API -> Sends to localhost:8080/IPv4Data.
    - File -> Saved packets to JSON file.
    - Console -> Prints packets to console.

### **3️⃣ Running the Packet Scanner**
```bash
cd PacketScanner
go run main.go
```

### **4️⃣ Generating Network Traffic**
To ensure data is captured, send traffic to the target IP using:
```bash
ping <TARGET_IP>
```