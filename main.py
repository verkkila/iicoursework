#!/usr/bin/env python

from sys import argv
from questions import answer
import socket
import struct
import encryption

VERBOSE_MODE = False
SERVER_ADDRESS = ""
TCP_PORT = -1
CLIENT_UDP_PORT = 10000
SERVER_UDP_PORT = -1
UDP_MSG_FORMAT = "!??HH64s"
INITIAL_UDP_MSG = "Ekki-ekki-ekki-ekki-PTANG."
PARAMETERS = "C"
ENCODING = "latin-1"

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
        print("Verbose mode enabled.")
        
    if len(argv) < 3:
        print("Usage: main.py [server_address] [port] [flags]")
        return False
    else:
        SERVER_ADDRESS = argv[1]
        try:
            port = int(argv[2])
        except ValueError:
            print("Port must be a decimal number.")
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

def encrypt_msg(msg):
    global CLIENT_KEY_COUNTER
    vprint("Encrypting with client key({}): {}".format(CLIENT_KEY_COUNTER, CLIENT_KEYS[CLIENT_KEY_COUNTER]))
    encrypted_msg = encryption.encrypt(msg, CLIENT_KEYS[CLIENT_KEY_COUNTER])
    CLIENT_KEY_COUNTER += 1
    assert(CLIENT_KEY_COUNTER < 20)
    return encrypted_msg
    
def get_UDP_message(eom, ack, message):
    msg_len = len(message)
    remaining_data = 0
    if "C" in PARAMETERS:
        out_msg = encrypt_msg(message)
    else:
        out_msg = message
    return struct.pack(UDP_MSG_FORMAT, eom, ack, msg_len, remaining_data, out_msg.encode(ENCODING))

def main():
    global SERVER_KEYS, CLIENT_UDP_PORT, SERVER_UDP_PORT, SERVER_KEY_COUNTER
    if not parse_args():
        return
    for i in range(0, 20):
        CLIENT_KEYS.append(encryption.generate_key_64())
    vprint("Server address: {} port: {}".format(SERVER_ADDRESS, TCP_PORT))
    server_ip = socket.gethostbyname(SERVER_ADDRESS)
    #Do TCP handshake
    TCP_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    vprint("(TCP) Attempting to connect to: {} port: {}".format(server_ip, TCP_PORT))
    TCP_sock.connect((server_ip, TCP_PORT))
    hello_msg = " ".join(["HELO", str(CLIENT_UDP_PORT), PARAMETERS])
    if "C" in PARAMETERS:
        TCP_msg = "\r\n".join([hello_msg, "\r\n".join(CLIENT_KEYS), ".\r\n"]).encode(ENCODING)
    else:
        TCP_msg = hello_msg.encode("utf-8")
    vprint("(TCP) Sending: {}".format(TCP_msg))
    TCP_sock.send(TCP_msg)
    recv_hello = TCP_sock.recv(16).decode("utf-8").strip("\r\n").split(" ")
    #Check encryption keys sent by the server
    if "C" in PARAMETERS:
        keys = TCP_sock.recv(2048).decode("utf-8")
        SERVER_KEYS = keys.split("\r\n")[0:-2]
        for key in SERVER_KEYS:
            valid_keys = True
            valid_keys = encryption.verify_key(key)
        if valid_keys:
            vprint("Verified {} keys from the server".format(len(SERVER_KEYS)))
    TCP_sock.close()
    #Parse TCP message
    SERVER_UDP_PORT = int(recv_hello[1])
    recv_params = ""
    if len(PARAMETERS) > 0:
        recv_params = recv_hello[2]
    if sorted(recv_params) != sorted(PARAMETERS):
        vprint("Client and server parameters don't match")
    vprint("(TCP) Received:\n\tUDP port: {}\n\tParameters: {}\n\tKeys: {}\n".format(SERVER_UDP_PORT, recv_params, len(SERVER_KEYS)))
    #Start UDP communication
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    vprint("Starting UDP communication, attempting to bind port {}".format(CLIENT_UDP_PORT))
    #Bind the first UDP port in range 10000-10100
    while True:
        try:
            recv_sock.bind(("", CLIENT_UDP_PORT))
            vprint("Bound UDP socket on port {}".format(CLIENT_UDP_PORT))
            break
        except socket.error:
            CLIENT_UDP_PORT += 1
            if CLIENT_UDP_PORT > 10100:
                print("Error! Ran out of possible UDP ports, exiting...")
                return
    first_UDP_msg = get_UDP_message(False, True, INITIAL_UDP_MSG)
    vprint("(UDP) Sending to {} on port {}".format(server_ip, SERVER_UDP_PORT))
    recv_sock.sendto(first_UDP_msg, (server_ip, SERVER_UDP_PORT))
    vprint("(UDP) Sent: {}\n".format(first_UDP_msg))
    while True:
        vprint("(UDP) Waiting to receive...")
        recv_data, recv_addr = recv_sock.recvfrom(128)
        #vprint("(UDP) Received: {}".format(recv_data))
        EOM, ACK, msg_len, remaining_data_len, raw_msg = struct.unpack(UDP_MSG_FORMAT, recv_data)
        if EOM:
            print("Server: {}".format(raw_msg.decode(ENCODING)))
            break
        if "C" in PARAMETERS:
            vprint("Decrypting with server key({}):{}".format(SERVER_KEY_COUNTER, SERVER_KEYS[SERVER_KEY_COUNTER]))
            raw_msg = encryption.decrypt(raw_msg.strip(b"\x00").decode(ENCODING), SERVER_KEYS[SERVER_KEY_COUNTER])
            SERVER_KEY_COUNTER += 1
        else:
            raw_msg = raw_msg.decode("utf-8")
        print("Server: {}".format(raw_msg))
        out_msg = answer(raw_msg)
        print("Client: {}".format(out_msg))
        UDP_msg = get_UDP_message(False, True, out_msg)
        vprint("(UDP) Sending: {}\n".format(UDP_msg))
        recv_sock.sendto(UDP_msg, (server_ip, SERVER_UDP_PORT))
    recv_sock.close()

if __name__ == "__main__":
    main()
