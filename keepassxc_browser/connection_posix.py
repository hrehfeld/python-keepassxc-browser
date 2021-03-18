import socket


class DefaultSock:

    def __init__(self, timeout, buff_size):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buff_size)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buff_size)

    def connect(self, address):
        try:
            self.sock.connect(address)
        except socket.error:
            self.sock.close()
            raise Exception(
                "Could not connect to {addr}".format(addr=address)
            )

    def close(self):
        self.sock.close()

    def send(self, message):
        self.sock.send(message)

    def recvfrom(self, buff_size):
        return self.sock.recvfrom(buff_size)
