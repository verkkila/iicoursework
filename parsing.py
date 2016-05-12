import sys
from socket import gethostbyname

def get_ip_and_port():
    try:
        addr = sys.argv[1]
        ipaddr = gethostbyname(addr)
        port = int(sys.argv[2])
    except (IndexError, ValueError):
        print("Could not resolve ip address or port.")
        return ("", -1)
    return (ipaddr, port)

def get_port(message):
    """
    
    """
    split = message.split(" ")
    try:
        port = int(split[1])
    except (ValueError, IndexError):
        print("Could not parse port from [{}].".format(message))
        return -1
    return port

def get_parameters(message):
    split = message.split("\r\n")[0].split(" ")
    try:
        params = "".join(split[2].rstrip("\r\n"))
    except IndexError:
        print("Could not parse parameters from [{}].".format(message))
        return ""
    return params

def get_encryption_keys(message, key_count=20):
    temp_keys = message.rstrip("\r\n").split("\r\n")[1:]
    assert(temp_keys[key_count] == ".")
    return temp_keys[:-1]

def replace_port(message, port):
    split = message.split(" ")
    split[1] = str(port)
    return " ".join(split)
