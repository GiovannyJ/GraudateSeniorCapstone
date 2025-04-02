# Detect OS
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
    MOVE := move
    PYTHON := python3
    SEP := \\
else
    DETECTED_OS := Unix
    MOVE := mv
    PYTHON := python3
    SEP := /
endif

run: build web

# Running the web server
web:
	cd WebServer && $(PYTHON) manage.py runserver 8080 &

# Building the binaries for packetsniffer and packet env
build: build_packet build_malpacket

build_packet: 
	cd PacketSniffer && go build -o ../WebServer$(SEP)ProcessRunner$(SEP)packetsniffer
#$(MOVE) PacketSniffer$(SEP)packetsniffer WebServer$(SEP)ProcessRunner$(SEP)packetsniffer

build_malpacket:
	cd Malpacket && go build -o ../WebServer$(SEP)ProcessRunner$(SEP)malpacket
	
#$(MOVE) Malpacket$(SEP)malpacket WebServer$(SEP)ProcessRunner$(SEP)packetsniffer
