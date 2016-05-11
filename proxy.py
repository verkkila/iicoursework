#!/usr/bin/env python
import socket
import sys

VERBOSE_MODE = False
ENCODING = "utf-8"

PROXY_TCP_PORT = -1
PROXY_UDP_PORT = -1

CLIENT_IP = ""
CLIENT_UDP_PORT = -1

SERVER_IP = ""
SERVER_TCP_PORT = -1
SERVER_UDP_PORT = -1

def init(verbose, encoding, server_ip, tcp_port):
    global VERBOSE_MODE, ENCODING, SERVER_IP, SERVER_TCP_PORT
    VERBOSE_MODE = verbose
    SERVER_IP = server_ip
    SERVER_TCP_PORT = tcp_port
    ENCODING = encoding

def vprint(msg):
    if VERBOSE_MODE:
        print(msg)
    else:
        pass

def bind_socket(sock, port_start=10000, port_end=10000):
    socktype = "socktype"
    if sock.type == 1:
        socktype = "TCP"
    elif sock.type == 2:
        socktype = "UDP"
    while True:
        try:
            sock.bind(("", port_start))
            vprint("Bound {} socket on port {}".format(socktype, port_start))
            return port_start
        except socket.error:
            port_start += 1
            if port_start > port_end:
                print("Failed to bind {} socket".format(socktype))

def replace_port(message, port):
    msg_split = message.split(" ")
    msg_split[1] = str(port)
    return " ".join(msg_split)

def get_port(message):
    split_message = message.split(" ")
    try:
        port = int(split_message[1])
    except (ValueError, IndexError):
        print("Could not find port from message: {}".format(message))
        return -1
    return port

def get_parameters(message):
    split_message = message.split(" ")
    try:
        params = split_message[2]
        assert(sorted(params) in "ACIM")
    except IndexError:
        print("Parameters not found.")
        return ""
    return params

def recv_all(conn, end_marker="\r\n"):
    recv_buf = []
    while True:
        recv_data = conn.recv(64).decode(ENCODING)
        recv_buf.append(recv_data)
        if end_marker in recv_data:
            break
    return "".join(recv_buf)

def handle_TCP_connection(conn, addr):
    global CLIENT_IP, CLIENT_UDP_PORT, SERVER_UDP_PORT
    CLIENT_IP = addr[0]
    print("(TCP) Received connection from: {}".format(addr))
    recv_data = conn.recv(32).decode(ENCODING)
    client_helo = recv_data.split("\r\n")[0]
    vprint("(TCP) 1. HELO C->P: {}".format(client_helo))
    remaining_data = ""
    end_marker = "\r\n"
    if "C" in client_helo:
        end_marker = "."
        remaining_data = recv_all(conn, end_marker)
    full_recv = "".join([recv_data, remaining_data])
    client_msg = full_recv
    CLIENT_UDP_PORT = get_port(client_msg)
    assert(CLIENT_UDP_PORT != -1)
    mod_client_msg = replace_port(client_msg, PROXY_UDP_PORT).encode(ENCODING)      
    mod_helo_cl = mod_client_msg.decode(ENCODING).split("\r\n")[0]
    server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_conn.connect((SERVER_IP, SERVER_TCP_PORT))
    vprint("(TCP) 2. HELO P->S: {}".format(mod_helo_cl))
    server_conn.sendall(mod_client_msg)
    server_response = recv_all(server_conn, end_marker)
    server_helo = server_response.split("\r\n")[0]
    vprint("(TCP) 3. HELO S->P: {}".format(server_helo))
    server_conn.close()
    SERVER_UDP_PORT = get_port(server_response)
    assert(SERVER_UDP_PORT != -1)
    mod_server_response = replace_port(server_response, PROXY_UDP_PORT).encode(ENCODING)
    mod_helo_sv = mod_server_response.decode(ENCODING).split("\r\n")[0]
    vprint("(TCP) 4. HELO P->C: {}".format(mod_helo_sv))
    conn.sendall(mod_server_response)
        
def forward_UDP_packets(sock):
    EOM = False
    while not EOM:
        print("(UDP) Waiting to receive...")
        recv_data, conn_info = sock.recvfrom(128)
        packet_length = len(recv_data)
        if recv_data[0] != 0:
            print("(UDP) Received EOM.")
            EOM = True
        if conn_info[0] == CLIENT_IP:
            vprint("(UDP) Received {} bytes from: {}".format(packet_length, CLIENT_IP))
            vprint("(UDP) Forwarding {} bytes to: {}".format(packet_length, SERVER_IP))
            sock.sendto(recv_data, (SERVER_IP, SERVER_UDP_PORT))
        elif conn_info[0] == SERVER_IP:
            vprint("(UDP) Received {} bytes from: {}".format(packet_length, CLIENT_IP))
            print("(UDP) Forwarding {} bytes to: {}".format(packet_length, SERVER_IP))
            sock.sendto(recv_data, (CLIENT_IP, CLIENT_UDP_PORT))
        else:
            vprint("(UDP) Received {} bytes from unknown: {}".format(packet_length, conn_info[0]))

def start():
    global PROXY_TCP_PORT, PROXY_UDP_PORT
    TCP_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    UDP_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    PROXY_TCP_PORT = bind_socket(TCP_sock)
    PROXY_UDP_PORT = bind_socket(UDP_sock)
    assert(PROXY_TCP_PORT != -1 and PROXY_UDP_PORT != -1)
    while True:
        TCP_sock.listen(5)
        print("(TCP) Listening for connections.")
        connection, address = TCP_sock.accept()
        handle_TCP_connection(connection, address)
        connection.close()
        forward_UDP_packets(UDP_sock)
    TCP_sock.close()
    UDP_sock.close()

def print_help():
    print("Usage: proxy.py [server_address] [port] [options]\n\
-h\t--help\tPrint help.\n\
-v\t--verbose\tPrints additional information.\n")

def parse_args():
    global VERBOSE_MODE, SERVER_IP, SERVER_TCP_PORT

    if "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        return False

    if "-v" in sys.argv or "--verbose" in sys.argv:
        VERBOSE_MODE = True
        vprint("Verbose mode enabled.")

    try:
        addr = sys.argv[1]
        SERVER_IP = socket.gethostbyname(addr)
        assert(SERVER_IP != "")
        port = int(sys.argv[2])
    except (socket.gaierror, ValueError, IndexError):
        print("Usage: proxy.py [server_address] [port] [options]")
        return False
    else:
        if port >= 0 and port <= 65535:
            SERVER_TCP_PORT = port
        else:
            print("Port not in range 0-65535.")
            return False
    return True  

if __name__ == "__main__":
    if parse_args():
        start()
    
