# Cybersecurity Packet Sniffer & AI Model Integration  

## **Created By:** Angel and Giovanny  

This project consists of a **network packet sniffer**, an **AI model**, and a **web server** to display captured data in real-time. It allows packets to be sent to an API or saved to a file for further analysis.  

---

## **📂 Project Structure**  


### **MalPacket/**
- **`helper/`** - Contains helper functions for packet routing.  
- **`MalPacketAtkMethods/`** - Contains different attack methods possible with IPv4 TCP packets.  
- **`malpacketcreate.go`** - The main driver for simulating a malicious packet environment.  Will send all information **internally** as a loopback system.



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
### **AI_Scripts/** 
- **`datasets/`** - Different datasets uses to train and test the AI model
- **`AI_Model_Trainer.py`** - The main driver for the AI model
  - contains classes to load and preprocess data, as well as train and test the AI model

### **models/**
- different models saved from the trained AI

### **myapp/** (Main Web Application)  
#### **templates/**  
- **`dynamictest.html`** - The web page displaying IPv4 data via AJAX (auto-refresh every **1 second**).  

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
python3 -m pip install -r requirements.txt
cd WebServer
python3 manage.py runserver 8080
```
**Within the web server triggers the launch the Packet Scanner and simulated networks binaries are made.**

### Alternatively
**In the root directory:**
```bash
make run
```

**This will build the binaries for the packet scanner and simulated network, move their files to the proper directory, and run the web server all in one step.**

---
## **The following steps are depreciated**

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
Generating normal and anomalous traffic:
```bash
cd MalPacket
go run malpacketcreate.go
```

----
### KNOWN ISSUES
- When using the application with Windows11 network APIs do not work to detect the network interface.
