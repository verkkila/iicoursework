import sys
from encryption import verify_key
from socket import gethostbyname, gaierror

def get_ip_and_port():
    try:
        addr = sys.argv[1]
        ipaddr = gethostbyname(addr)
        port = int(sys.argv[2])
    except (IndexError, ValueError, gaierror):
        print("Could not resolve ip address or port.")
        return ("", -1)
    return (ipaddr, port)

def get_port(message):
    split = message.split(" ")
    try:
        port = int(split[1])
    except (ValueError, IndexError):
        print("Could not parse port from: {}".format(message))
        return -1
    return port

def get_parameters(message):
    split = message.split("\r\n")[0].split(" ")
    try:
        params = "".join(split[2].rstrip("\r\n"))
    except IndexError:
        print("Could not parse parameters from: {}".format(message))
        return ""
    return params

def get_encryption_keys(message, key_count=20):
    try:
        temp_keys = message.rstrip("\r\n").split("\r\n")[1:]
        assert(temp_keys[key_count] == ".")
        keys_final = temp_keys[:-1]
        for key in keys_final:
            assert(verify_key(key))
    except (IndexError, AssertionError):
        print("Failed to get encryption keys from: {}".format(message))
        keys_final = []
    return keys_final

def replace_port(message, port):
    split = message.split(" ")
    try:
        split[1] = str(port)
    except IndexError:
        print("Could not replace port in: {}".format(message))
        return ""
    return " ".join(split)
