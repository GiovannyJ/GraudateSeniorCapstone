import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 8080))  # Listen on port 8080
server.listen(5)

print("Waiting for a connection...")
client_socket, addr = server.accept()
print(f"Received connection from {addr}")

client_socket.send(b"Hello, this is a TCP test from 8.8.8.8\n")
client_socket.close()
