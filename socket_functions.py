import socket
import sys

ENCODING = sys.getdefaultencoding()

def recv_all(conn):
    try:
        header = conn.recv(32, socket.MSG_PEEK).decode(ENCODING)
    except UnicodeDecodeError:
        print("(TCP) Bad header received: {}".format(header))
        return ""
    except socket.timeout:
        print("(TCP) Connection was established, but no data received.")
        return ""
    helo = header.split("\r\n")[0]
    end_marker = "\r\n"
    if "C" in helo:
        end_marker = "."
    recv_buf = []
    while True:
        try:
            recv_data = conn.recv(512).decode(ENCODING)
        except socket.timeout:
            print("(TCP) Did not receive correct end marker, returning possible HELO: {}".format(helo))
            return helo
        if recv_data:
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
