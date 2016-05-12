import socket
import sys

BUF_SIZE = 128
ENCODING = sys.getdefaultencoding()

def recv_all(conn):
    header = conn.recv(32, socket.MSG_PEEK).decode(ENCODING)
    helo = header.split("\r\n")[0]
    end_marker = "\r\n"
    if "C" in helo:
        end_marker = "."
    recv_buf = []
    while True:
        recv_data = conn.recv(BUF_SIZE).decode(ENCODING)
        recv_buf.append(recv_data)
        if end_marker in recv_data:
            break
    return "".join(recv_buf)

def bind_socket(sock, current_port=10000, last_port=10099):
    first_port = current_port
    if sock.type == socket.SOCK_STREAM:
        socktype = "TCP"
    else:
        socktype = "UDP"
    while True:
        try:
            sock.bind(("", current_port))
            print("Bound {} socket on port {}".format(socktype, current_port))
            return current_port
        except socket.error:
            current_port += 1
            if current_port > last_port:
                print("Failed to bind {} socket in range {}-{}".format(socktype, first_port, last_port))
                return -1

def is_EOM(char):
    major_version = sys.version_info[0]
    if major_version == 3:
        return char
    else:
        return ord(char)
