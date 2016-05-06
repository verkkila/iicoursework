#!/usr/bin/env python

from sys import argv
import socket
import struct
import encryption

SERVER_ADDRESS = "ii.virtues.fi"
TCP_PORT = 10000
UDP_PORT = 10000
VERBOSE_MODE = False

#EOM-ACK-content_length-data_remaining-content
#bool-bool-ushort-ushort-char[64]
#1+1+2+2+64==70
#Ekki-ekki-ekki-ekki-PTANG.

CLIENT_KEYS = []
SERVER_KEYS = []

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
    
def main():
    global SERVER_KEYS, UDP_PORT
    if not parse_args():
        vprint("Failed to parse cmdline args.")
        return
    for i in range(0, 20):
        CLIENT_KEYS.append(encryption.generate_key_64())
    vprint("Server address: {} port: {}".format(SERVER_ADDRESS, TCP_PORT))
    server_ip = socket.gethostbyname(SERVER_ADDRESS)
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    vprint("Attempting to connect to: {} port: {}".format(server_ip, TCP_PORT))
    tcp_sock.connect((server_ip, TCP_PORT))
    initial_msg = "HELO 10000 C\r\n".encode("utf-8")
    tcp_sock.send(initial_msg)
    for key in CLIENT_KEYS:
        tcp_sock.send((key + "\r\n").encode("utf-8"))
    tcp_sock.send(".\r\n".encode("utf-8"))
    recv_data = tcp_sock.recv(2048)
    vprint(recv_data)
    tcp_sock.close()
    split_data = recv_data.decode("utf-8").split("\r\n")
    hello_msg = split_data[0].split(" ")
    UDP_PORT = int(hello_msg[1])
    parameters = hello_msg[2]
    SERVER_KEYS = split_data[1:-2]
    vprint(UDP_PORT)
    vprint(SERVER_KEYS)
    vprint(len(SERVER_KEYS))

if __name__ == "__main__":
    main()
