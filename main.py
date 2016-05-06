#!/usr/bin/env python

from sys import argv
from questions import answer
import socket
import struct
import encryption

SERVER_ADDRESS = "ii.virtues.fi"
TCP_PORT = 10000
CLIENT_UDP_PORT = 10000
SERVER_UDP_PORT = 10000
VERBOSE_MODE = False
UDP_MSG_FORMAT = "!??HH64s"
INITIAL_UDP_MSG = "Ekki-ekki-ekki-ekki-PTANG."
PARAMETERS = "C"

#EOM-ACK-content_length-data_remaining-content
#bool-bool-ushort-ushort-char[64]
#1+1+2+2+64==70

CLIENT_KEYS = []
SERVER_KEYS = []
CLIENT_KEY_COUNTER = 0
SERVER_KEY_COUNTER = 0

def print_help():
    print("Usage: main.py [server_address] [port] [flags]")
    print("Possible flags:")
    print("-h\t--help\t\tPrint help.")
    print("-v\t--verbose\tPrint additional information.")

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
    
def get_udp_message(eom, ack, message):
    global CLIENT_KEY_COUNTER
    msg_len = len(message)
    remaining_data = 0
    vprint("Using key {}".format(CLIENT_KEY_COUNTER+1))
    encrypted_data = encryption.encrypt(message, CLIENT_KEYS[CLIENT_KEY_COUNTER]).encode("utf-8")
    CLIENT_KEY_COUNTER += 1
    assert(CLIENT_KEY_COUNTER < 20)
    return struct.pack(UDP_MSG_FORMAT, eom, ack, msg_len, remaining_data, encrypted_data)

def main():
    global SERVER_KEYS, CLIENT_UDP_PORT, SERVER_UDP_PORT
    if not parse_args():
        print("Failed to parse cmdline args.")
        return
    for i in range(0, 20):
        CLIENT_KEYS.append(encryption.generate_key_64())
    vprint("Server address: {} port: {}".format(SERVER_ADDRESS, TCP_PORT))
    server_ip = socket.gethostbyname(SERVER_ADDRESS)
    TCP_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    vprint("(TCP) Attempting to connect to: {} port: {}".format(server_ip, TCP_PORT))
    TCP_sock.connect((server_ip, TCP_PORT))
    first_tcp_msg = "\r\n".join([" ".join(["HELO", str(CLIENT_UDP_PORT), PARAMETERS]), "\r\n".join(CLIENT_KEYS), ".\r\n"]).encode("utf-8")
    vprint("(TCP) Sending: {}".format(first_tcp_msg))
    TCP_sock.send(first_tcp_msg)
    hello_msg = TCP_sock.recv(32).decode("utf-8")
    keys = TCP_sock.recv(2048).decode("utf-8")
    SERVER_UDP_PORT = int(hello_msg.split(" ")[1])
    parameters = hello_msg.split(" ")[2]
    SERVER_KEYS = keys.split("\r\n")[0:-2]
    vprint("(TCP) Received:\n\tUDP port: {}\n\tParameters: {}".format(SERVER_UDP_PORT, parameters))
    for key in SERVER_KEYS:
        valid_keys = True
        valid_keys = encryption.verify_key(key)
    if valid_keys:
        vprint("Received and verified {} keys from the server".format(len(SERVER_KEYS)))
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    vprint("Starting UDP communication, binding port {}".format(CLIENT_UDP_PORT))
    recv_sock.bind(("127.0.0.1", CLIENT_UDP_PORT))
    first_udp_msg = get_udp_message(False, True, INITIAL_UDP_MSG)
    send_sock.sendto(first_udp_msg, (server_ip, SERVER_UDP_PORT))
    vprint("(UDP) Sent: {}".format(first_udp_msg))
    UDP_active = True
    while UDP_active:
        recv_data, recv_addr = recv_sock.recvfrom(128)
        vprint(recv_data)
        vprint(recv_addr)
        EOM, ACK, msg_len, remaining_data_len, encrypted_msg = struck.unpack(UDP_MSG_FORMAT, recv_data)
        vprint("{} {} {} {} {}".format(eom, ack, msg_len, remaining_data_len, encrypted_msg.decode("utf-8").strip("\x00")))
        if EOM:
            UDP_active = True
        decrypted_msg = encryption.decrypt(encrypted_msg, SERVER_KEYS[SERVER_KEY_COUNTER])
        SERVER_KEY_COUNTER += 1
    send_sock.close()
    recv_sock.close()
    TCP_sock.close()

if __name__ == "__main__":
    main()
