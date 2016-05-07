#!/usr/bin/env python

from sys import argv
from questions import answer
import socket
import struct
import encryption

VERBOSE_MODE = False
SERVER_ADDRESS = ""
SERVER_IP = ""
TCP_PORT = -1
CLIENT_UDP_PORT = 10000
SERVER_UDP_PORT = -1
UDP_MSG_FORMAT = "!??HH64s"
INITIAL_UDP_MSG = "Ekki-ekki-ekki-ekki-PTANG."
PARAMETERS = "CI"
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

def request_UDP_resend(sock, reason):
    vprint(reason)
    UDP_msg = get_UDP_message(False, False, "Send again.")
    sock.sendto(UDP_msg, (SERVER_IP, SERVER_UDP_PORT))

def main():
    global SERVER_IP, SERVER_KEYS, CLIENT_UDP_PORT, SERVER_UDP_PORT, SERVER_KEY_COUNTER
    if not parse_args():
        return
    for i in range(0, 20):
        CLIENT_KEYS.append(encryption.generate_key_64())
    vprint("Server address: {} port: {}".format(SERVER_ADDRESS, TCP_PORT))
    SERVER_IP = socket.gethostbyname(SERVER_ADDRESS)
    TCP_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    UDP_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #Bind the first UDP port in range 10000-10100
    while True:
        try:
            UDP_sock.bind(("", CLIENT_UDP_PORT))
            vprint("Bound UDP socket on port {}".format(CLIENT_UDP_PORT))
            break
        except socket.error:
            CLIENT_UDP_PORT += 1
            if CLIENT_UDP_PORT > 10100:
                print("ERROR: Ran out of possible UDP ports, exiting...")
                return
    vprint("(TCP) Attempting to connect to: {} port: {}".format(SERVER_IP, TCP_PORT))
    TCP_sock.connect((SERVER_IP, TCP_PORT))
    hello_msg = " ".join(["HELO", str(CLIENT_UDP_PORT), PARAMETERS])
    if "C" in PARAMETERS:
        TCP_msg = "\r\n".join([hello_msg, "\r\n".join(CLIENT_KEYS), ".\r\n"]).encode(ENCODING)
    else:
        TCP_msg = hello_msg.encode(ENCODING)
    vprint("(TCP) Sending initial message.".format(TCP_msg))
    TCP_sock.send(TCP_msg)
    #Get port and parameters from server's response
    server_hello_msg = TCP_sock.recv(16).decode(ENCODING).strip("\r\n").split(" ")
    SERVER_UDP_PORT = int(server_hello_msg[1])
    recv_params = ""
    if len(PARAMETERS) > 0:
        recv_params = server_hello_msg[2]
    if sorted(recv_params) != sorted(PARAMETERS):
        vprint("Client and server parameters don't match.")
    #Check encryption keys sent by the server
    if "C" in PARAMETERS:
        keys = TCP_sock.recv(2048).decode(ENCODING)
        SERVER_KEYS = keys.split("\r\n")[0:-2]
        for key in SERVER_KEYS:
            valid_keys = True
            valid_keys = encryption.verify_key(key)
        if valid_keys:
            vprint("Verified {} keys from the server.".format(len(SERVER_KEYS)))
        else:
            #TODO handle this case
            pass
    TCP_sock.close()
    vprint("(TCP) Received:\n\tUDP port: {}\n\tParameters: {}\n\tKeys: {}\n".format(SERVER_UDP_PORT, recv_params, len(SERVER_KEYS)))
    #Start UDP communication
    vprint("Starting UDP communication, attempting to bind port {}".format(CLIENT_UDP_PORT))
    first_UDP_msg = get_UDP_message(False, True, INITIAL_UDP_MSG)
    vprint("(UDP) Sending to {} on port {}".format(SERVER_IP, SERVER_UDP_PORT))
    UDP_sock.sendto(first_UDP_msg, (SERVER_IP, SERVER_UDP_PORT))
    vprint("(UDP) Sent: {}\n".format(first_UDP_msg))
    while True:
        vprint("(UDP) Waiting to receive...")
        recv_data, recv_info = UDP_sock.recvfrom(128)
        #Check ip and port
        vprint("(UDP) Received: {}".format(recv_data))
        if recv_info[0] != SERVER_IP or recv_info[1] != SERVER_UDP_PORT:
            request_UDP_resend(UDP_sock, "Server address and/or port mismatch.")
            continue
        try:
            EOM, ACK, msg_len, remaining_data_len, raw_msg = struct.unpack(UDP_MSG_FORMAT, recv_data)
        except struct.error:
            request_UDP_resend(UDP_sock, "Received invalid packet from server.")
            continue
        vprint("EOM: {}\nACK: {}\nMessage length: {}\nRemaining data: {}\nRaw message: {}".format(EOM, ACK, msg_len, remaining_data_len, raw_msg))
        if EOM:
            print("Server: {}".format(raw_msg.decode(ENCODING)))
            break
        #Compare given message length to actual message length
        if msg_len != len(raw_msg):
            request_UDP_resend(UDP_sock, "Message length field does not match actual message length.")
            continue
        print("Server: {}".format(raw_msg))
        #Attempt to decrypt the server's message
        if "C" in PARAMETERS:
            vprint("Decrypting with server key({}):{}".format(SERVER_KEY_COUNTER, SERVER_KEYS[SERVER_KEY_COUNTER]))
            raw_msg = encryption.decrypt(raw_msg.strip(b"\x00").decode(ENCODING), SERVER_KEYS[SERVER_KEY_COUNTER])
            if raw_msg == "BADMSG":
                request_UDP_resend(UDP_sock, "Could not decrypt message.")
                continue
            SERVER_KEY_COUNTER += 1
        else:
            raw_msg = raw_msg.decode(ENCODING)
        #Check for a valid answer
        out_msg = answer(raw_msg)
        if out_msg == "":
            request_UDP_resend(UDP_sock, "Did not find an answer for the server's question.")
            continue
        print("Client: {}".format(out_msg))
        UDP_msg = get_UDP_message(False, True, out_msg)
        vprint("(UDP) Sending: {}\n".format(UDP_msg))
        UDP_sock.sendto(UDP_msg, (SERVER_IP, SERVER_UDP_PORT))

    UDP_sock.close()

if __name__ == "__main__":
    main()
