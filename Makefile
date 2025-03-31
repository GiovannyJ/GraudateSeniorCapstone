.PHONY: all web packet mal

all: web packet mal

web:
	cd WebServer && python manage.py runserver 8080 &

packet:
	cd PacketSniffer && go run main.go

mal:
	cd Malpacket && go run malpacketcreate.go


Make a thing to compile PacketSniffer
compile Malpacket
Move to WebServer/ProcessRunner/ * 
