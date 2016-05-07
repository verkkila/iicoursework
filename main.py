#!/usr/bin/env python

from sys import argv
from questions import answer
import socket
import struct
import encryption

VERBOSE_MODE = False
ENCODING = "latin-1"
SERVER_ADDRESS = ""
SERVER_IP = ""
TCP_PORT = -1
CLIENT_UDP_PORT = 10000
SERVER_UDP_PORT = -1
UDP_MSG_FORMAT = "!??HH64s"
CLIENT_PARAMETERS = "CIA"
SERVER_PARAMETERS = ""

NUM_KEYS = 0
CLIENT_KEYS = []
SERVER_KEYS = []
CLIENT_KEY_COUNTER = 0
SERVER_KEY_COUNTER = 0

def print_help():
    print("Usage: main.py [server_address] [port] [options]")
    print("Possible options:")
    print("-h\t--help\t\tPrint help.")
    print("-v\t--verbose\tPrints additional information.")

def parse_args():
    global SERVER_ADDRESS, TCP_PORT, VERBOSE_MODE
    
    if "-h" in argv or "--help" in argv:
        print_help()
        return False
    
    if "-v" in argv or "--verbose" in argv:
        VERBOSE_MODE = True
        vprint("Verbose mode enabled.")
        
    if len(argv) < 3:
        print("Usage: main.py [server_address] [port] [options]")
        return False
    else:
        SERVER_ADDRESS = argv[1]
        try:
            port = int(argv[2])
        except ValueError:
            print("Port must be a decimal number.")
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

def have_client_keys():
    return CLIENT_KEY_COUNTER < NUM_KEYS

def have_server_keys():
    return SERVER_KEY_COUNTER < NUM_KEYS

def generate_keys(count):
    global NUM_KEYS, CLIENT_KEYS
    NUM_KEYS = count
    for i in range(0, NUM_KEYS):
        CLIENT_KEYS.append(encryption.generate_key_64())

def TCP_handshake():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    vprint("(TCP) Attempting to connect to: {} port: {}".format(SERVER_IP, TCP_PORT))
    sock.connect((SERVER_IP, TCP_PORT))
    #Construct HELO message
    hello_msg = " ".join(["HELO", str(CLIENT_UDP_PORT), CLIENT_PARAMETERS])
    if "C" in CLIENT_PARAMETERS:
        full_msg = "\r\n".join([hello_msg, "\r\n".join(CLIENT_KEYS), ".\r\n"]).encode(ENCODING)
    else:
        full_msg = "".join([hello_msg, "\r\n"]).encode(ENCODING)
    vprint("(TCP) Sending initial message.")
    sock.send(full_msg)
    #Receive response from server
    recvbuf = []
    while True:
        recv = sock.recv(128).decode(ENCODING)
        if recv == "":
            break
        recvbuf.append(recv)
    server_response = "".join(recvbuf)
    vprint("(TCP) Received {} bytes from the server.".format(len(server_response)))
    get_port_and_parameters(server_response)
    if "C" in CLIENT_PARAMETERS:
        get_encryption_keys(server_response)
    vprint("(TCP) Received:\n\tUDP port: {}\n\tParameters: {} (expected {})\n\tKeys: {} (expected {})".format(SERVER_UDP_PORT, SERVER_PARAMETERS, CLIENT_PARAMETERS, len(SERVER_KEYS), NUM_KEYS))
    sock.close()

def get_port_and_parameters(server_response):
    global SERVER_UDP_PORT, SERVER_PARAMETERS
    #Get port and parameters from server's response
    server_hello = server_response.split("\r\n")[0]
    SERVER_UDP_PORT = int(server_hello.split(" ")[1])
    assert(SERVER_UDP_PORT >= 0 and SERVER_UDP_PORT <= 65535)
    if CLIENT_PARAMETERS != "": 
        SERVER_PARAMETERS = server_hello.split(" ")[2]
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
    assert(CLIENT_KEY_COUNTER < NUM_KEYS)
    vprint("Encrypting with client key({}): {}".format(CLIENT_KEY_COUNTER, CLIENT_KEYS[CLIENT_KEY_COUNTER]))
    encrypted_msg = encryption.encrypt(msg, CLIENT_KEYS[CLIENT_KEY_COUNTER])
    CLIENT_KEY_COUNTER += 1
    return encrypted_msg
    
def get_UDP_message(eom, ack, message):
    msg_len = len(message)
    remaining_data = 0
    if "C" in CLIENT_PARAMETERS and have_client_keys():
        out_msg = encrypt_msg(message)
    else:
        out_msg = message
    return struct.pack(UDP_MSG_FORMAT, eom, ack, msg_len, remaining_data, out_msg.encode(ENCODING))

def request_UDP_resend(sock, reason):
    vprint(reason)
    UDP_msg = get_UDP_message(False, False, "Send again.")
    vprint("(UDP) Requesting server to send again.\n")
    sock.sendto(UDP_msg, (SERVER_IP, SERVER_UDP_PORT))

def main():
    global SERVER_IP, CLIENT_UDP_PORT, SERVER_KEY_COUNTER, NUM_KEYS
    if not parse_args():
        return
    if "C" in CLIENT_PARAMETERS:
        generate_keys(20)
    try:
        SERVER_IP = socket.gethostbyname(SERVER_ADDRESS)
    except socket.gaierror:
        print("Could not resolve server ip address.")
        return
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
    TCP_handshake()
    #Start UDP communication
    vprint("(UDP) Starting UDP communication.")
    UDP_msg_initial = get_UDP_message(False, True, "Ekki-ekki-ekki-ekki-PTANG.")
    vprint("(UDP) Sending to {} on port {}".format(SERVER_IP, SERVER_UDP_PORT))
    UDP_sock.sendto(UDP_msg_initial, (SERVER_IP, SERVER_UDP_PORT))
    vprint("(UDP) Sent initial message.\n")
    while True:
        vprint("(UDP) Waiting to receive...")
        recv_data, recv_info = UDP_sock.recvfrom(128)
        #Check ip and port
        if recv_info[0] != SERVER_IP or recv_info[1] != SERVER_UDP_PORT:
            request_UDP_resend(UDP_sock, "Server address and/or port mismatch.")
            continue
        try:
            EOM, ACK, msg_len, remaining_data_len, content_raw = struct.unpack(UDP_MSG_FORMAT, recv_data)
        except struct.error:
            request_UDP_resend(UDP_sock, "Received invalid packet from server.")
            continue
        vprint("(UDP) Received:\n\tEOM: {}\n\tACK: {}\n\tMessage length: {}\n\tRemaining data: {}\n\tRaw content: {}".format(EOM, ACK, msg_len, remaining_data_len, content_raw))
        if EOM:
            print("Server: {}".format(content_raw.decode(ENCODING)))
            break
        #Attempt to decrypt the server's message
        if "C" in CLIENT_PARAMETERS and have_server_keys():
            assert(SERVER_KEY_COUNTER < NUM_KEYS)
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
        if msg_len != len(content):
            request_UDP_resend(UDP_sock, "Message length field does not match actual message length.")
            continue
        #Check for a valid answer
        response = answer(content)
        if response == "":
            request_UDP_resend(UDP_sock, "Did not find an answer for the server's question.")
            continue
        print("Server: {}".format(content))
        print("Client: {}".format(response))
        UDP_msg = get_UDP_message(False, True, response)
        vprint("(UDP) Sending message.\n")
        UDP_sock.sendto(UDP_msg, (SERVER_IP, SERVER_UDP_PORT))
    UDP_sock.close()

if __name__ == "__main__":
    main()
