import socket

tcp_socket = socket.create_connection(('127.0.0.1', 9999))

try:
    data = str.encode("Hi! I am a TCP client, nice to meet you!")
    tcp_socket.sendall(data)
finally:
    print("Closing socket!")
    tcp_socket.close()