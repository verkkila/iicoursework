#!/usr/bin/env python
import socket
import sys
import parsing
from socket_functions import bind_socket, recv_all, is_EOM

VERBOSE_MODE = False
ENCODING = sys.getdefaultencoding()
RECV_WAIT_TIME = 10

PROXY_TCP_PORT = -1
PROXY_UDP_PORT = -1

CLIENT_IP = ""
CLIENT_UDP_PORT = -1

SERVER_IP = ""
SERVER_TCP_PORT = -1
SERVER_UDP_PORT = -1

def print_help():
    print("Usage: proxy.py [server_address] [port] [options]\n\
-h\t--help\tPrint help.\n\
-v\t--verbose\tPrints additional information.\n")

def set_config():
    global VERBOSE_MODE
    if "-h" in sys.argv:
        print_help()
        return False
    if "-v" in sys.argv:
        VERBOSE_MODE = True
    return True

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

def handle_TCP_connection(conn, addr):
    global CLIENT_IP, CLIENT_UDP_PORT, SERVER_UDP_PORT
    CLIENT_IP = addr[0]
    print("(TCP) Received connection from: {}".format(addr))
    recv_client = recv_all(conn)
    client_helo = recv_client.split("\r\n")[0]
    vprint("(TCP) 1. HELO Client --> Proxy: {}".format(client_helo))
    CLIENT_UDP_PORT = parsing.get_port(recv_client)
    assert(CLIENT_UDP_PORT != -1)
    cl_TCP_msg_MOD = parsing.replace_port(recv_client, PROXY_UDP_PORT).encode(ENCODING)      
    cl_HELO_MOD = cl_TCP_msg_MOD.decode(ENCODING).split("\r\n")[0]
    #BEGIN server
    server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_conn.connect((SERVER_IP, SERVER_TCP_PORT))
    vprint("(TCP) 2. HELO Proxy --> Server: {}".format(cl_HELO_MOD))
    server_conn.sendall(cl_TCP_msg_MOD)
    recv_server = recv_all(server_conn)
    server_helo = recv_server.split("\r\n")[0]
    vprint("(TCP) 3. HELO Server --> Proxy: {}".format(server_helo))
    SERVER_UDP_PORT = parsing.get_port(recv_server)
    server_conn.close()
    #END server
    assert(SERVER_UDP_PORT != -1)
    sv_TCP_msg_MOD = parsing.replace_port(recv_server, PROXY_UDP_PORT).encode(ENCODING)
    sv_HELO_MOD = sv_TCP_msg_MOD.decode(ENCODING).split("\r\n")[0]
    vprint("(TCP) 4. HELO Proxy --> Client: {}".format(sv_HELO_MOD))
    conn.sendall(sv_TCP_msg_MOD)
        
def forward_UDP_packets(sock):
    EOM = False
    print("(UDP) Starting UDP packet forwarding.")
    while not EOM:
        vprint("(UDP) Waiting to receive...")
        try:
            recv_data, conn_info = sock.recvfrom(128)
        except socket.timeout:
            print("(UDP) No traffic for 10 seconds, closing connection.")
            return
        packet_length = len(recv_data)
        if is_EOM(recv_data[0]):
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
    global SERVER_IP, SERVER_TCP_PORT, PROXY_TCP_PORT, PROXY_UDP_PORT
    if not set_config():
        return
    SERVER_IP, SERVER_TCP_PORT = parsing.get_ip_and_port()
    print("(TCP) Server is: {}".format((SERVER_IP, SERVER_TCP_PORT)))
    TCP_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    UDP_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDP_sock.settimeout(RECV_WAIT_TIME)
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

if __name__ == "__main__":
    try:
        start()
    except KeyboardInterrupt:
        print("Exiting...")
