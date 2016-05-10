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

def init(verbose, server_ip, tcp_port):
    global VERBOSE_MODE, SERVER_IP, SERVER_TCP_PORT
    VERBOSE_MODE = verbose
    SERVER_IP = server_ip
    SERVER_TCP_PORT = tcp_port

def vprint(msg):
    if VERBOSE_MODE:
        print(msg)
    else:
        pass

def bind_TCP_socket(sock, port_start=10000, port_end=10099):
    global PROXY_TCP_PORT
    while True:
        try:
            sock.bind(("", port_start))
            vprint("Bound TCP socket on port {}".format(port_start))
            PROXY_TCP_PORT = port_start
            break
        except socket.error:
            port_start += 1
            if port_start > port_end:
                print("Failed to bind TCP port.")
                return
            
def bind_UDP_socket(sock, port_start=10000, port_end=10099):
    global PROXY_UDP_PORT
    while True:
        try:
            sock.bind(("", port_start))
            vprint("Bound UDP socket on port {}".format(port_start))
            PROXY_UDP_PORT = port_start
            break
        except socket.error:
            port_start += 1
            if port_start > port_end:
                print("Failed to bind TCP port.")
                return

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
    server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_conn.connect((SERVER_IP, SERVER_TCP_PORT))
    server_conn.send(mod_client_msg)
    server_response = recv_all(server_conn, end_marker)
    server_conn.close()
    SERVER_UDP_PORT = get_port(server_response)
    assert(SERVER_UDP_PORT != -1)
    mod_server_response = replace_port(server_response, PROXY_UDP_PORT).encode(ENCODING)
    print(mod_server_response)
    conn.sendall(mod_server_response)
        
def forward_UDP_packets(sock):
    while True:
        print("(UDP) Waiting to receive...")
        recv_data, conn_info = sock.recvfrom(128)
        if conn_info[0] == CLIENT_IP:
            vprint("(UDP) Received packet from: {}".format(CLIENT_IP))
            sock.sendto(recv_data, (SERVER_IP, SERVER_UDP_PORT))
            vprint("(UDP) Forwarding to: {}".format(SERVER_IP))
        else:
            vprint("(UDP) Received packet from: {}".format(CLIENT_IP))
            sock.sendto(recv_data, (CLIENT_IP, CLIENT_UDP_PORT))
            print("(UDP) Forwarding to: {}".format(SERVER_IP))
        if recv_data[0] != 0:
            print("(UDP) Received EOM.")
            break

def start(TCP_port=10000, TCP_port_max=10099, UDP_port=10000, UDP_port_max=10099):
    TCP_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    UDP_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bind_TCP_socket(TCP_sock)
    bind_UDP_socket(UDP_sock)

    while True:
        TCP_sock.listen(1)
        print("(TCP) Listening for connections.")
        connection, address = TCP_sock.accept()
        handle_TCP_connection(connection, address)
        connection.close()
        forward_UDP_packets(UDP_sock)
    TCP_sock.close()
    UDP_sock.close()

def print_help():
    print("Usage: proxy.py [real_server_address] [port] [options]\n\
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
        print("Usage: proxy.py [real_server_address] [port] [options]")
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
    
