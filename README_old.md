# Created By: Angel and Giovanny
Cyber
    datasets
    AI_model.py:
        This is where the route model of our AI will live.
    API.py:
        This is a test instance of how an API can be used to get the information from the network packet scanner
        there is on POST route on localhost:8080/IPv4Data that is used to collect the data in the shape of 
        ```
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
                "Payload": "CADxQ7UoAAfrvZ5nAAAAAPuTDQAAAAAAEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nw=="
            },
            "checksum": 0,
            "ttl": 64,
            "version": 4,
            "tos": 0,
            "payload": "..ñCµ(..ë½.g....û.\r..................."
        }
        ```
PacketSniffer
    API
        sendToAI.go:
            This file holds the method to send IPv4ScanResults to the API at the address IPv4Data through a POST request
    file
        filehandler.go:
            This file holds the method to send IPv4ScanResults to a file, named in the shape of 'session_data_DATE_TIME.json'
            The information in the JSON file will be shaped as:
            NOTE: as of right now this is not proper JSON format, there is a missing ']' at the end of the file. Fixes for this will be made later as for now just manually enter this into the file.
            ```
            [
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
                    "Contents": "RQAAVLBGAABAAQAAwKgAhwgICAg=",
                    "Payload": "CADhe8E8AAMy655nAAAAALseCgAAAAAAEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nw=="
                },
                "checksum": 0,
                "ttl": 64,
                "version": 4,
                "tos": 0,
                "payload": "..á{Á\u003c..2ë.g....».\n..................... !\"#$%\u0026'()*+,-./01234567"
                },
                {
                "type": "IPv4",
                "source": "8.8.8.8",
                "destination": "192.168.0.135",
                "protocol": "ICMPv4",
                "flags": null,
                "frag_offset": 0,
                "ihl": 5,
                "length": 84,
                "options": null,
                "padding": null,
                "base_layer": {
                    "Contents": "RQAAVAAAAAA5AbBqCAgICMCoAIc=",
                    "Payload": "AADpe8E8AAMy655nAAAAALseCgAAAAAAEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nw=="
                },
                "checksum": 45162,
                "ttl": 57,
                "version": 4,
                "tos": 0,
                "payload": "..é{Á\u003c..2ë.g....».\n..................... !\"#$%\u0026'()*+,-./01234567"
                }
             
            ```
    helper
        helper.go:
            This file contains a method to clean the payload that is recieved in the IPv4 Packets and convert its contents to printable and readable unicode. It also contains macros for console prints to make them more readable.
    packet
        packersniffer.go:
            This file is the core functionality of the packet sniffer. The current process for packet sniffing goes as follows
                -gather OS specific network gateway interface
                -open live handle to packets being processed by this interface
                -iterate through the packets as they come
                -determine mode of sniff
                -send to proper location
                    -mode: API or api -> send to API endpoint http://localhost:8080/IPv4Data
                    -mode: File or file -> send to session file named after date and time
                    -mode: <EMPTY_STRING> -> send to console
    structs
        stucts.go:
            This file contains the shapes of data that will be interfaced with in processing phase along with some helper functionality.
    main.go:
        This is the main entry point into the packet sniffer in which the user can define what type of mode they would like to run in (API/File/none):

PCAP_Files: Contained in this folder are all of the packet capture files in JSON format

WebServer: This is the web server that runs an API endpoint as well as hosts the main web page for this application
    myapp: the main directory to edit files for this application
        templates
            display_data.html:
                This is the main web page that will render the data that is fed through the API. When data is present it will render in the table using AJAX. This process is automatic and does not require a page refresh. The current process takes 1 second to request for data, this can be tweaked to be faster or slower as seen fit
        urls.py
            This file defines the endpoints of the webapp. The current two endpoints being '' or default and 'IPv4Data' which renders a JSON response page is used as the POST endpoint for the web app effectively becoming our API. The default page that is rendered displays the 'display_data.html' page with the request data as context.
        views.py
            This file contains the logic that is triggered when the webapp receives the request to their particular endpoints. There is a global live_data list that is used to store the IPv4 data per session. This data will not persist and only lives per session. The ipv4_data function is what loads the POST request data from 'localhost:8080/IPv4Data' into the global live_data variable. It ill return a JSON response depending on if there is a success or an error. The display_data function handles the request from the default endpoint of the webapp and renders the 'display_data.html' page with the current version of live_data.
    WebServer
        settings.py
            This is the configuration file. The only variable that was changed was the INSTALLED_APPS list, appended to it was 'myapp'. This is what allowed the web app to be processed by the Django web server.
        urls.py
            In this file is where where include access to the urls in the myapp directory.
    mange.py
        This is the main entry point of the webserver.


How to run
Running the webserver
-ensure you are in the 'WebServer' directory 
```cd WebServer```
-start the webserver
```python manage.py runserver 8080```

Running the PacketScanner
-ensure you are in the 'PacketSniffer' directory
```cd PacketSniffer```
-to choose a target, edit the ip address of the targetIP variable
-to choose a run mode edit the second argument of the p.Sniff() function
-start the packet sniffer
```go run main.go```
-make sure that the is traffic to the desired target IP by opening a new terminal and entering the command 
```ping <TARGET_IP>```
