import socket

from library.Crypt import generate_rsa


class Server:

    def __init__(self, ip, port, keypair=None, keybits=4096):
        self.s:socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((ip, port))
        self.s.listen()
        self.keypair = keypair
        if not self.keypair:
            self.keypair:tuple = generate_rsa(keybits)
        self.nodes:list = {} # publicKey:(ip, port)

    def accept_command():
        pass
