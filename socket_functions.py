import socket
BUF_SIZE = 128

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
    socktype = "socktype"
    if sock.type == 1:
        socktype = "TCP"
    elif sock.type == 2:
        socktype = "UDP"
    while True:
        try:
            sock.bind(("", current_port))
            print("Bound {} socket on port {}".format(socktype, current_port))
            return current_port
        except socket.error:
            current_port += 1
            if current_port > last_port:
                print("Failed to bind {} socket".format(socktype))


