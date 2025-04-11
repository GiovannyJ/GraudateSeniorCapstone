import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    
    def do_POST(self):
        # Check if the request is made to /IPv4Data endpoint
        if self.path == '/IPv4Data':
            # Get content length to read the incoming data
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            # Try to parse JSON data from the request
            try:
                data = json.loads(post_data)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()

                # Print received data in a readable format
                #! THIS IS WHERE YOU WOULD PUT IT TO THE AI STUFF
                print(json.dumps(data, indent=4))

                # Respond back to the client with a success message
                response = {
                    "message": "IPv4 data received successfully!"
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))

            except json.JSONDecodeError as e:
                # If JSON is invalid, respond with an error
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {
                    "error": "Invalid JSON"
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            # Handle other requests if needed (optional)
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {
                "error": "Not Found"
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))

def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting server on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()

