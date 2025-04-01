# Detect OS
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
    MOVE := move
    PYTHON := python
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
	cd PacketSniffer && go build -o packetsniffer.exe
	$(MOVE) PacketSniffer$(SEP)packetsniffer.exe WebServer$(SEP)ProcessRunner$(SEP)packetsniffer.exe

build_malpacket:
	cd Malpacket && go build -o malpacket.exe
	$(MOVE) Malpacket$(SEP)malpacket.exe WebServer$(SEP)ProcessRunner$(SEP)malpacket.exe

