import argparse
import socket
import shlex  # this library is designed for only Unix shells. Otherwise, it can cause command injection vulnerability
import subprocess
import sys
import textwrap
import threading


def run_command(cmd):
    cmd = cmd.strip()  # remove spaces at the beginning and at the end of the string
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT, shell=True)
    return output.decode()


def client_sender(buffer):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((args.target, args.port))
        if len(buffer):
            client.send(buffer.encode())
        while True:
            recv_len = 1
            response = ""
            while recv_len:
                data = client.recv(4096)
                recv_len = len(data)
                response += data.decode()

                if recv_len < 4096:
                    break
            print(response, end='')
            buffer = input("")
            if buffer.strip():
                buffer += "\n"
                client.send(buffer.encode())

    except ConnectionRefusedError:
        print("[*] Connection refused! Closing...")
    except Exception as e:
        print(f"[*] Exception: {str(e)}. Closing...")
    finally:
        client.close()


def server_loop():
    global target
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((target, args.port))
    server.listen(5)

    while True:
        client_socket, addr = server.accept()
        # Thread to handle new client
        client_thread = threading.Thread(target=client_handler, args=(client_socket,))
        client_thread.start()


def client_handler(client_socket):
    global upload_destination
    global command
    global execute_command

    if len(upload_destination):
        file_buffer = b""
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            else:
                file_buffer += data
        # attempt to save the loaded bytes
        try:
            file_descriptor = open(args.upload_destination, "wb")
            file_descriptor.write(file_buffer)
            file_descriptor.close()

            # confirmation of saving file
            client_socket.send("File saved in {upload_destination}\r\n")
        except:
            client_socket.send("Couldn't save file in {upload_destination}\r\n")

    if len(execute_command):
        output = run_command(execute_command)
        client_socket.send(output)
    if command:
        while True:
            # send simple command line
            client_socket.send("<FATUM:#> ".encode())
            # retrieve text until new line mark is encountered (Enter key)
            cmd_buffer = "".encode()
            while b"\n" not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024)
            response = run_command(cmd_buffer.decode())
            client_socket.send(response.encode())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Netcat made by Amor Fati',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent('''Examples:

            netcat.py -t <TARGET> -p <PORT> -l -c
            netcat.py -t <TARGET> -p <PORT> -l -u=<FILE>
            netcat.py -t <TARGET> -p <PORT> -l -e=\"cat /etc/passwd\"
            echo 'ABCDEFG' | ./netcat.py -t 192.168.11.12 -p 135
        '''))
    parser.add_argument('-t', '--target', default='0.0.0.0', help='specified ip')
    parser.add_argument('-p', '--port', type=int, default=1234, help='specified port')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-e', '--execute', help='execute specified command', default="")
    parser.add_argument('-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-u', '--upload-destination', help='upload file', default="")
    args = parser.parse_args()

    target = args.target
    upload_destination = args.upload_destination
    execute_command = args.execute
    command = args.command

    if args.listen:
        server_loop()
    else:
        buffer = sys.stdin.read()
        client_sender(buffer)
