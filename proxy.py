import socket
import sys

ENCODING = "utf-8"
PROXY_TCP_PORT = -1
PROXY_UDP_PORT = -1
CLIENT_UDP_PORT = -1
SERVER_UDP_PORT = -1
CLIENT_IP = ""
SERVER_IP = ""
SERVER_ADDRESS = "ii.virtues.fi"
SERVER_TCP_PORT = 10000

def bind_TCP_socket(sock, port_start=10000, port_end=10099):
    global PROXY_TCP_PORT
    
    while True:
        try:
            sock.bind(("", port_start))
            print("Bound TCP socket on port {}".format(port_start))
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
            print("Bound UDP socket on port {}".format(port_start))
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
    assert(split_message[0] == "HELO")
    try:
        port = int(split_message[1])
    except ValueError:
        print("Could not find port from message: {}".format(message))
        return -1
    return port

def forward_UDP_packets(sock):
    while True:
        print("(UDP) Waiting to receive...")
        recv_data, conn_info = sock.recvfrom(128)
        if conn_info[0] == CLIENT_IP:
            print("(UDP) Received packet from: {}".format(CLIENT_IP))
            sock.sendto(recv_data, (SERVER_IP, SERVER_UDP_PORT))
            print("(UDP) Forwarding to: {}".format(SERVER_IP))
        else:
            print("(UDP) Received packet from: {}".format(CLIENT_IP))
            sock.sendto(recv_data, (CLIENT_IP, CLIENT_UDP_PORT))
            print("(UDP) Forwarding to: {}".format(SERVER_IP))
        if recv_data[0] != 0:
            print("(UDP) Received EOM.")
            break

def start(TCP_port=10000, TCP_port_max=10099, UDP_port=10000, UDP_port_max=10099):
    global CLIENT_UDP_PORT, SERVER_UDP_PORT, CLIENT_IP, SERVER_IP

    SERVER_IP = socket.gethostbyname(SERVER_ADDRESS)
    assert(SERVER_IP != "")
    
    TCP_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    UDP_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    bind_TCP_socket(TCP_sock)
    bind_UDP_socket(UDP_sock)

    while True:
        TCP_sock.listen(1)
        print("(TCP) Listening for connections.")
        connection, address = TCP_sock.accept()
        CLIENT_IP = address[0]
        print("(TCP) Received connection: {}".format(address))
        recv_data = connection.recv(4096)
        client_msg = recv_data.decode(ENCODING)
        CLIENT_UDP_PORT = get_port(client_msg)
        assert(CLIENT_UDP_PORT != -1)
        modified_client_helo = replace_port(client_msg, PROXY_UDP_PORT).encode(ENCODING)
        
        server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_conn.connect((SERVER_ADDRESS, SERVER_TCP_PORT))
        server_conn.send(modified_client_helo)
        server_response = server_conn.recv(4096).decode(ENCODING)
        server_conn.close()
        SERVER_UDP_PORT = get_port(server_response)
        assert(SERVER_UDP_PORT != -1)
        modified_server_helo = replace_port(server_response, PROXY_UDP_PORT).encode(ENCODING)
        connection.sendall(modified_server_helo)
        connection.close()

        forward_UDP_packets(UDP_sock)
    TCP_sock.close()
    UDP_sock.close()
    

if __name__ == "__main__":
    start()
