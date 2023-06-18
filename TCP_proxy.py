import sys
import socket
import threading
import argparse
import textwrap


def server_loop(
        local_host,
        local_port,
        remote_host,
        remote_port,
        receive_first
):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except:
        print(f"[!!] Failed attempt to listen on port {local_host, local_port}")
        print("Try to find another socket, or gain proper privileges.")
        sys.exit(0)
    finally:  # I added this finally, for aesthetic reasons, if it causes problems, I will delete that
        print(f"[*] Listening on port {local_host, local_port}")
        server.listen(5)
        while True:
            client_socket, addr = server.accept()
            print(f"[==>] Received incoming connection from {addr[0], addr[1]}")

            # running thread to cooperate with remote host
            proxy_thread = threading.Thread(target=proxy_handler,
                                            args=(client_socket, remote_host, remote_port, receive_first))
            proxy_thread.start()


def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))
    # collecting data from host (such as ftp banners) is needed
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

        # sending data to response handling procedure
        remote_buffer = response_handler(remote_buffer)

        # if we have data to send to local client, we send them, also check later for adding encode() and decode() funcs
        if len(remote_buffer):
            print(f"[<==] Sending {len(remote_buffer)} to localhost.")
            client_socket.send(remote_buffer)
    # also this line of code may have indentation problems
        while True:
            local_buffer = receive_from(client_socket)
            if len(local_buffer):
                print(f"[==>] Received {len(local_buffer)} bytes from localhost.")
                hexdump(local_buffer)

                local_buffer = request_handler(local_buffer)

                remote_socket.send(local_buffer)
                print("[==>] Sent data to remote host.")

                remote_buffer = receive_from(remote_socket)

                if len(remote_buffer):
                    print(f"[<==] Received {len(remote_buffer)} bytes from remote host")
                    hexdump(remote_buffer)

                    remote_buffer = response_handler(remote_buffer)
                    print("[<==] Sent to localhost.")
            if not len(local_buffer) or not len(remote_buffer):
                client_socket.close()
                remote_socket.close()
                print("[*] There is no more data. Closing connections.")
                break


def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2
    for i in range(0, len(src), length):
        s = src[i:i+length]
        hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append(b"%04X %-*s %s" % (i, length*(digits + 1), hexa, text))

    print(b'\n'.join(result))


def receive_from(connection):
    buffer = ""
    connection.settimeout(2)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except:
        pass
    finally:
        return buffer


def request_handler(buffer):
    return buffer


def response_handler(buffer):
    return buffer


# I'm not really sure if this main function should exist in this exception :/
def main():
    parser = argparse.ArgumentParser(
        description='TCP Proxy server by Amor Fati',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent(''' Example: 
            python TCP_proxy.py [localhost] [localport] [remotehost] [remoteport] [receivefirst]
            python TCP_proxy.py 127.0.0.1 9000 10.12.132.1 9000 True
        '''))
    parser.add_argument('local_host', help='specified local ip')
    parser.add_argument('local_port', type=int, help='specified local port')
    parser.add_argument('remote_host', help='specified remote ip')
    parser.add_argument('remote_port', type=int, help='specified remote port')
    parser.add_argument('receive_first', help='specified receive first (True/False)')
    args = parser.parse_args()

    local_host = args.local_host
    local_port = args.local_port
    remote_host = args.remote_host
    remote_port = args.remote_port
    receive_first = args.receive_first

    if "True" in receive_first:
        receive_first = True
    elif "true" in receive_first:
        receive_first = True
    elif "t" in receive_first:
        receive_first = True
    else:
        receive_first = False

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

    # print(type(local_host), type(local_port), type(remote_host), type(remote_port), type(receive_first))
    # print(local_host, local_port, remote_host, remote_port, receive_first)

main()
