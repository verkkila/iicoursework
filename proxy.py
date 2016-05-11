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

def bind_socket(sock, current_port=10000, last_port=10099):
    socktype = "socktype"
    if sock.type == 1:
        socktype = "TCP"
    elif sock.type == 2:
        socktype = "UDP"
    while True:
        try:
            sock.bind(("", current_port))
            vprint("Bound {} socket on port {}".format(socktype, current_port))
            return current_port
        except socket.error:
            current_port += 1
            if current_port > last_port:
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

def recv_all(conn):
    header = conn.recv(32, socket.MSG_PEEK).decode(ENCODING)
    helo = header.split("\r\n")[0]
    end_marker = "\r\n"
    if "C" in helo:
        end_marker = "."
    recv_buf = []
    while True:
        recv_data = conn.recv(128).decode(ENCODING)
        recv_buf.append(recv_data)
        if end_marker in recv_data:
            break
    return "".join(recv_buf)

def handle_TCP_connection(conn, addr):
    global CLIENT_IP, CLIENT_UDP_PORT, SERVER_UDP_PORT
    CLIENT_IP = addr[0]
    print("(TCP) Received connection from: {}".format(addr))
    recv_client = recv_all(conn)
    client_helo = recv_client.split("\r\n")[0]
    vprint("(TCP) 1. HELO Client --> Proxy: {}".format(client_helo))
    CLIENT_UDP_PORT = get_port(recv_client)
    assert(CLIENT_UDP_PORT != -1)
    cl_TCP_msg_MOD = replace_port(recv_client, PROXY_UDP_PORT).encode(ENCODING)      
    cl_HELO_MOD = cl_TCP_msg_MOD.decode(ENCODING).split("\r\n")[0]
    #BEGIN server
    server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_conn.connect((SERVER_IP, SERVER_TCP_PORT))
    vprint("(TCP) 2. HELO Proxy --> Server: {}".format(cl_HELO_MOD))
    server_conn.sendall(cl_TCP_msg_MOD)
    recv_server = recv_all(server_conn)
    server_helo = recv_server.split("\r\n")[0]
    vprint("(TCP) 3. HELO Server --> Proxy: {}".format(server_helo))
    SERVER_UDP_PORT = get_port(recv_server)
    server_conn.close()
    #END server
    assert(SERVER_UDP_PORT != -1)
    sv_TCP_msg_MOD = replace_port(recv_server, PROXY_UDP_PORT).encode(ENCODING)
    sv_HELO_MOD = sv_TCP_msg_MOD.decode(ENCODING).split("\r\n")[0]
    vprint("(TCP) 4. HELO Proxy --> Client: {}".format(sv_HELO_MOD))
    conn.sendall(sv_TCP_msg_MOD)
        
def forward_UDP_packets(sock):
    EOM = False
    print("(UDP) Starting UDP packet forwarding.")
    while not EOM:
        vprint("(UDP) Waiting to receive...")
        recv_data, conn_info = sock.recvfrom(128)
        packet_length = len(recv_data)
        if recv_data[0] != 0:
            print("(UDP) Received EOM.")
            EOM = True
        if conn_info[0] == CLIENT_IP:
            vprint("(UDP) Received {} bytes from (client): {}".format(packet_length, CLIENT_IP))
            vprint("(UDP) Forwarding {} bytes to (server): {}".format(packet_length, SERVER_IP))
            sock.sendto(recv_data, (SERVER_IP, SERVER_UDP_PORT))
        elif conn_info[0] == SERVER_IP:
            vprint("(UDP) Received {} bytes from (server): {}".format(packet_length, SERVER_IP))
            vprint("(UDP) Forwarding {} bytes to (client): {}".format(packet_length, CLIENT_IP))
            sock.sendto(recv_data, (CLIENT_IP, CLIENT_UDP_PORT))
        else:
            vprint("(UDP) Received {} bytes from unknown: {}".format(packet_length, conn_info[0]))

def start():
    global PROXY_TCP_PORT, PROXY_UDP_PORT
    print("(TCP) Server is: {}".format((SERVER_IP, SERVER_TCP_PORT)))
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
        connection.shutdown(socket.SHUT_RDWR)
        forward_UDP_packets(UDP_sock)
        connection.close()
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
    
