#!/usr/bin/env python

import sys
import socket
import struct
import encryption
from questions import answer

VERBOSE_MODE = False
PROXY_MODE = False
ENCODING = ""
UDP_PACKET_FORMAT = "!??HH64s"

SERVER_IP = ""
TCP_PORT = -1
CLIENT_UDP_PORT = 10010
SERVER_UDP_PORT = -1

CLIENT_PARAMETERS = ""
SERVER_PARAMETERS = ""

NUM_KEYS = 0
CLIENT_KEY_COUNTER = 0
SERVER_KEY_COUNTER = 0
CLIENT_KEYS = []
SERVER_KEYS = []

def print_help():
    print("Usage: main.py [server_address] [port] [options]\n\
-h\t--help\t\tPrints help.\n\
-v\t--verbose\tPrints additional information.\n\
-e\t--encrypt\tUse encryption when communicating over UDP (Python3).\n\
-p\t--proxy\tStarts the program in proxy mode.")


def parse_options():
    global VERBOSE_MODE, PROXY_MODE, CLIENT_PARAMETERS
    if "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        return False

    if "-v" in sys.argv or "--verbose" in sys.argv:
        VERBOSE_MODE = True
        vprint("Verbose mode enabled.")

    if "-p" in sys.argv or "--proxy" in sys.argv:
        PROXY_MODE = True
        vprint("Starting as a proxy server.")
        return True

    if "-e" in sys.argv or "--encrypt" in sys.argv:
        if sys.version_info[0] == 3:
            CLIENT_PARAMETERS += "C"
            vprint("Using encryption.")
        else:
            result = raw_input("Encryption not supported in Python2. Continue in plaintext? (y/n):")
            if "n" in result:
                print("Exiting...")
                return False
            
def parse_args():
    global SERVER_IP, TCP_PORT,
    if not parse_options():
        return False
    try:
        addr = sys.argv[1]
        SERVER_IP = socket.gethostbyname(addr)
        assert(SERVER_IP != "")
        port = int(sys.argv[2])
    except (socket.gaierror, ValueError, IndexError):
        print("Usage: main.py [server_address] [port] [options]")
        return False
    else:
        if port >= 0 and port <= 65535:
            TCP_PORT = port
        else:
            print("Port not in range 0-65535.")
            return False
    return True

def vprint(msg):
    if VERBOSE_MODE:
        print(msg)
    else:
        pass

def debug_print_globals():
    print("VERBOSE_MODE: {}".format(VERBOSE_MODE))
    print("ENCODING: {}".format(ENCODING))
    print("UDP_PACKET_FORMAT: {}".format(UDP_PACKET_FORMAT))
    print("SERVER_IP: {}".format(SERVER_IP))
    print("TCP_PORT: {}".format(TCP_PORT))
    print("CLIENT_UDP_PORT: {}".format(CLIENT_UDP_PORT))
    print("SERVER_UDP_PORT: {}".format(SERVER_UDP_PORT))
    print("CLIENT_PARAMETERS: {}".format(CLIENT_PARAMETERS))
    print("SERVER_PARAMETERS: {}".format(SERVER_PARAMETERS))
    print("NUM_KEYS: {}".format(NUM_KEYS))
    print("CLIENT_KEY_COUNTER: {}".format(CLIENT_KEY_COUNTER))
    print("SERVER_KEY_COUNTER: {}".format(SERVER_KEY_COUNTER))


def have_client_keys():
    return CLIENT_KEY_COUNTER < NUM_KEYS

def have_server_keys():
    return SERVER_KEY_COUNTER < NUM_KEYS

def use_encryption():
    return "C" in CLIENT_PARAMETERS

def generate_encryption_keys(count=20):
    global NUM_KEYS, CLIENT_KEYS
    NUM_KEYS = count
    for i in range(0, NUM_KEYS):
        CLIENT_KEYS.append(encryption.generate_key_64())

def TCP_handshake(sock):
    vprint("(TCP) Attempting to connect to: {} port: {}".format(SERVER_IP, TCP_PORT))
    sock.connect((SERVER_IP, TCP_PORT))
    #Construct HELO message
    hello_msg = " ".join(["HELO", str(CLIENT_UDP_PORT), CLIENT_PARAMETERS])
    if use_encryption():
        full_msg = "\r\n".join([hello_msg, "\r\n".join(CLIENT_KEYS), ".\r\n"]).encode(ENCODING)
    else:
        full_msg = "".join([hello_msg, "\r\n"]).encode(ENCODING)
    vprint("(TCP) Sending initial message.")
    sock.sendall(full_msg)
    #Receive response from server
    recvbuf = []
    while True:
        recv_data = sock.recv(128).decode(ENCODING)
        if recv_data == "":
            break
        recvbuf.append(recv_data)
    server_response = "".join(recvbuf)
    vprint("(TCP) Received {} bytes from the server.".format(len(server_response)))
    result = get_port_and_parameters(server_response)
    if use_encryption():
        result = get_encryption_keys(server_response)
    vprint("(TCP) Received:\n\tUDP port: {}\n\tParameters: {} (expected {})\n\tKeys: {} (expected {})".format(SERVER_UDP_PORT, SERVER_PARAMETERS, CLIENT_PARAMETERS, len(SERVER_KEYS), NUM_KEYS))
    return result

def get_port_and_parameters(server_response):
    global SERVER_UDP_PORT, SERVER_PARAMETERS
    server_hello = server_response.split("\r\n")[0]
    SERVER_UDP_PORT = int(server_hello.split(" ")[1])
    assert(SERVER_UDP_PORT >= 0 and SERVER_UDP_PORT <= 65535)
    if CLIENT_PARAMETERS != "": 
        try:
            SERVER_PARAMETERS = server_hello.split(" ")[2]
        except IndexError:
            vprint("Failed to parse server parameters.")
            return False
    if sorted(SERVER_PARAMETERS) != sorted(CLIENT_PARAMETERS):
        vprint("Client and server parameters don't match.")
        return False
    return True

def get_encryption_keys(server_response):
    global SERVER_KEYS
    temp_keys = server_response.rstrip("\r\n").split("\r\n")[1:]
    assert(temp_keys[NUM_KEYS] == ".")
    SERVER_KEYS = temp_keys[:-1]
    assert(len(SERVER_KEYS) == NUM_KEYS)
    for key in SERVER_KEYS:
        if not encryption.verify_key(key):
            vprint("Received bad encryption key: {}".format(key))
            return False
    return True

def encrypt_msg(msg):
    global CLIENT_KEY_COUNTER
    vprint("Encrypting with client key({}): {}".format(CLIENT_KEY_COUNTER, CLIENT_KEYS[CLIENT_KEY_COUNTER]))
    encrypted_msg = encryption.encrypt(msg, CLIENT_KEYS[CLIENT_KEY_COUNTER])
    CLIENT_KEY_COUNTER += 1
    return encrypted_msg
    
def create_UDP_packets(eom, ack, content):
    pieces = [content[i:i+64] for i in range(0, len(content), 64)]
    packets = []
    remaining_data_length = len(content)
    for piece in pieces:
        content_length = len(piece)
        remaining_data_length -= len(piece)
        if use_encryption() and have_client_keys():
            content_final = encrypt_msg(piece)
        else:
            content_final = piece
        packets.append(struct.pack(UDP_PACKET_FORMAT, eom, ack, content_length, remaining_data_length, content_final.encode(ENCODING)))
    if len(packets) > 1:
        assert("M" in CLIENT_PARAMETERS)
    return packets

def send_UDP_packets(sock, packets):
    vprint("(UDP) Sending {} packet(s).".format(len(packets)))
    for packet in packets:
        sock.sendto(packet, (SERVER_IP, SERVER_UDP_PORT))

def request_UDP_resend(sock, reason):
    vprint(reason)
    packets = create_UDP_packets(False, False, "Send again.")
    vprint("(UDP) Requesting server to send again.\n")
    send_UDP_packets(sock, packets)

def main():
    global ENCODING, CLIENT_UDP_PORT, SERVER_KEY_COUNTER, NUM_KEYS
    if not parse_args():
        return
    ENCODING = sys.getdefaultencoding()
    if PROXY_MODE:
        proxy.init(VERBOSE_MODE, SERVER_IP, TCP_PORT)
        proxy.start()
        return
    if use_encryption():
        generate_encryption_keys()
        ENCODING = "latin-1"
    vprint("Server IP address: {} TCP port: {}".format(SERVER_IP, TCP_PORT))
    UDP_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #Bind the first UDP port in range 10000-10100
    while True:
        try:
            UDP_sock.bind(("", CLIENT_UDP_PORT))
            vprint("(UDP) Bound UDP socket on port {}".format(CLIENT_UDP_PORT))
            break
        except socket.error:
            CLIENT_UDP_PORT += 1
            if CLIENT_UDP_PORT > 10100:
                print("(UDP) Ran out of possible UDP sockets to bind, exiting...")
                return
    TCP_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if not TCP_handshake(TCP_sock):
        return
    #Start UDP
    vprint("(UDP) Starting UDP communication.")
    packets = create_UDP_packets(False, True, "Ekki-ekki-ekki-ekki-PTANG.")
    vprint("(UDP) Server ip {} port {}".format(SERVER_IP, SERVER_UDP_PORT))
    send_UDP_packets(UDP_sock, packets)
    vprint("(UDP) Sent initial message.\n")
    recvbuf = []
    while True:
        vprint("(UDP) Waiting to receive...")
        recv_data, conn_info = UDP_sock.recvfrom(128)
        #Check ip and port
        if conn_info[0] != SERVER_IP or conn_info[1] != SERVER_UDP_PORT:
            request_UDP_resend(UDP_sock, "Server address and/or port mismatch.")
            continue
        try:
            EOM, ACK, content_length, remaining_data_length, content_raw = struct.unpack(UDP_PACKET_FORMAT, recv_data)
        except struct.error:
            SERVER_KEY_COUNTER += 1
            request_UDP_resend(UDP_sock, "Received invalid packet from server.")
            continue
        vprint("(UDP) Received:\n\tEOM: {}\n\tACK: {}\n\tMessage length: {}\n\tRemaining data: {}\n\tRaw content: {}".format(EOM, ACK, content_length, remaining_data_length, content_raw))
        if EOM:
            print("Server: {}".format(content_raw.decode(ENCODING)))
            break
        #Attempt to decrypt the server's message
        if use_encryption() and have_server_keys():
            vprint("Decrypting with server key({}):{}".format(SERVER_KEY_COUNTER, SERVER_KEYS[SERVER_KEY_COUNTER]))
            content = encryption.decrypt(content_raw.strip(b"\x00").decode(ENCODING), SERVER_KEYS[SERVER_KEY_COUNTER])
            SERVER_KEY_COUNTER += 1
            if content == "BADMSG":
                request_UDP_resend(UDP_sock, "Could not decrypt message.")
                continue
            vprint("Decrypted: {}".format(content))
        else:
            content = content_raw.strip(b"\x00").decode(ENCODING)
        #Compare given message length to actual message length
        if content_length != len(content):
            request_UDP_resend(UDP_sock, "Message length field does not match actual message length.")
            continue
        recvbuf.append(content)
        if remaining_data_length > 0:
            continue
        #Check for a valid answer
        content_full = "".join(recvbuf)
        recvbuf = []
        response = answer(content_full)
        if response == "":
            request_UDP_resend(UDP_sock, "Did not find an answer for the server's question.")
            continue
        print("Server: {}".format(content_full))
        print("Client: {}".format(response))
        packets = create_UDP_packets(False, True, response)
        send_UDP_packets(UDP_sock, packets)
    TCP_sock.close()
    UDP_sock.close()

if __name__ == "__main__":
    main()
