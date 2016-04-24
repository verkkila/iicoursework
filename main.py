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

client_keys = []
server_keys = []

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
            if port >= 0 and port < 65536:
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
    global server_keys
    if not parse_args():
        vprint("Failed to parse cmdline args.")
        return
    vprint("Server address: {} port: {}".format(SERVER_ADDRESS, TCP_PORT))
    for i in range(0, 20):
        client_keys.append(encryption.generate_key_64())
    full_message = str.encode("\r\n".join(["HELO 10000 C", "\r\n".join(client_keys), "."]))
    deconstructed = full_message.decode("utf-8").split("\r\n")
    server_keys = deconstructed[1:len(deconstructed)-1]
    for key in server_keys:
        if not encryption.verify_key(key):
            print("Invalid encryption key")
    UDP_PORT = int(deconstructed[0].split(" ")[1])
    return
    server_ip = socket.gethostbyname(SERVER_ADDRESS)
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    vprint("Attempting to connect to: {} port: {}".format(server_ip, TCP_PORT))
    tcp_sock.connect((server_ip, TCP_PORT))
    vprint("Sending: {}".format(full_message))
    tcp_sock.send(full_message)
    recv_data = tcp_sock.recv(1536)
    tcp_sock.close()
    print(recv_data)

if __name__ == "__main__":
    main()
