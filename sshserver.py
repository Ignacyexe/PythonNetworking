# it's just for experimenting with paramiko
# right now this code is getting older because more and more Windows machines have ssh

import socket
import sys
import threading
import subprocess
import paramiko

host_key = paramiko.RSAKey(filename='test_rsa.key')


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:  # newer version of it
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        if (username == 'user') and (password == 'pass'):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED


server = sys.argv[1]
sshport = int(sys.argv[2])

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((server, sshport))
    sock.listen(100)
    print('Listening for connections...')
    client, add = sock.accept()
except Exception as e:
    print(f'Failed to listen, error code: {str(e)}')
    sys.exit(1)

print("[+] There is a connection!")

try:
    session = paramiko.Transport(client)
    session.add_server_key(host_key)
    server = Server()

    try:
        session.start_server(server=server)
    except paramiko.SSHException as x:
        print('[-] SSH negotiation failed.')

    chan = session.accept(20)
    print("[+] Authenticated!")
    print(chan.recv(1024))
    chan.send(b'Welcome to ssh!')

    while True:
        try:
            command = input("Insert command: ").strip("\n").encode()
            if command != "exit":
                chan.send(command)
                print(chan.recv(1024) + b"\n")
            else:
                chan.send(b'exit')
                print('exiting')
                session.close()
                raise Exception('exit')

        except KeyboardInterrupt:
            session.close()
except Exception as e:
    print("[-] Caught an Exception. " + str(e))
    try:
        session.close()
    except:
        pass

sys.exit(1)
