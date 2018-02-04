from pickle import dumps, UnpicklingError
import socket
from library.blockchain_data_type import Blockchain, Block, restricted_loads
import socketserver

# Aunque estemos sujetos al GIL, como la mayoría de operaciones son de I/O(red y accesos a disco),
# no afectaría al rendimiento (incluso sería contraproducente) lanzar procesos del sistema con multiproccesing
from threading import Thread

from math import ceil
from time import time
from random import choice


class MessageOverflow(Exception):

    pass


def mine(block, previous_hash, ceros=2):
    """
    Procedimiento para minar bloques(obviamente es de todo menos eficiente)
    :param block: Bloque a minar
    :param previous_hash: Hash anterior
    :param ceros: Número de ceros requeridos
    :return: None
    """
    content = block.content.get_content()
    block.set_header(block.hash(previous_hash))
    if "nonce" not in content:
        content["nonce"] = 0
    while block.get_header()[:ceros] != "0"*ceros:
        content["nonce"] += 1
        block.content.set_content(content)
        block.set_header(block.hash(previous_hash))


class Server(socketserver.ThreadingTCPServer):

    """
    Clase que se encarga de soportar todo el protocolo de comunicación haciendo de intérprete entre la blockchain y la
    red. La idea es que en producción se extienda para añadir las especificaciones del caso de uso de la blockchain
    """

    class HiloPeticion(socketserver.BaseRequestHandler):

        """
        Esta clase definirá todo el protocolo de comunicación. Parseará los comandos recibidos y
        ejecutará las funciones correspondientes sobre la blockchain
        """

        def handle(self):  # TODO Prueba de trabajo como método para evitar que se inunde la red de paquetes
            """
            Interfaz que redirecciona los comandos a su correspondiente función
            """
            self.request.settimeout(self.server.client_timeout)
            try:
                command = self.recv().split(b" ", 1)  # Obtenemos el op-code del comando
                if len(command) == 1:
                    command.append(b"")
                if command[0] in self.direccionamiento:
                    # Llamamos al comando correspondiente
                    self.send(self.direccionamiento[command[0]](self, command[1]))
                else:
                    self.send(b"INVALID_COMMAND")  # Notificamos que no reconocemos el comando
            except socket.timeout:
                self.send(b"TIMED_OUT")
            except MessageOverflow:
                self.send(b"MESSAGE_OVERFLOW")
            except socket.error:
                pass

        def register_node(self, args):
            comando = args.split(b" ")
            if len(comando) != 3:
                return b"FORMAT_ERROR"
            try:
                timestamp = int(comando[0])
                ip = str(comando[1], "ascii")
                port = int(str(comando[2], "ascii"))
            except ValueError:
                return b"FORMAT_ERROR"
            if self.add_node(b" ".join(comando[1:])) == b"SUCCESS":
                self.goship(b"register_node " + args, True, timestamp)  # Propagamos la petición de registro
                salir = time()
                while salir > time() - self.server.trial_add_node_on_register_timeout:
                    try:
                        # Intentamos notificar al nuevo nodo de nuestra existencia
                        self.server.query_to(b"add_node "+bytes(self.server.ip, "ascii")+b" " +
                                             bytes(str(self.server.port), "ascii"), ip, port, timeout=1)
                        salir = 0
                    except (socket.error, BlockingIOError):
                        pass
            else:
                # Propagamos la petición de registro
                self.goship(b"register_node " + args, False, timestamp)
            return b"SUCCESS"

        def add_block(self, args):
            """
            Protocolo para añadir un bloque a la blockchain
            :param args: Bloque a añadir
            :return: Bytes de estado
            """
            try:
                block: Block = restricted_loads(args)
            except (UnpicklingError, ValueError, EOFError):
                return b"FORMAT_ERROR"
            if block.timestamp > time():
                return b"TIMESTAMP_ERROR"
            result = self.server.add_block(block)
            if result == b"SUCCESS":
                self.goship(b"new_block "+args, True, block.timestamp)
            else:
                self.goship(b"new_block " + args, False, block.timestamp)
            return result

        def ping(self, ip, port):
            """
            Comprueba si un nodo responde a peticiones
            :param ip: Ip del nodo
            :param port: Puerto del nodo
            :return: ¿Esta el nodo en linea?
            """
            try:
                if self.server.query_to(b"asdf", ip, port, timeout=self.server.client_timeout) == b"INVALID_COMMAND":
                    return True
            except socket.error:
                return False

        def add_node(self, args: bytes):
            addr = args.split(b" ")
            try:
                addr = (str(addr[0], "ascii"), int(addr[1]))
                if len(addr) == 2 and self.ping(*addr):
                    return self.server.append_node(addr)
                raise ValueError
            except (ValueError, IndexError):
                return b"INVALID_HOST"

        def query_block(self, args):
            """
            Protocolo de solicitud de bloque
            :param args: bytes(index del comando)
            :return: dumps(bloque) o bytes("INVALID INDEX")
            """
            index = int.from_bytes(args, "big")
            try:
                return dumps(self.server.get_block(index))
            except IndexError:
                return b"INVALID_INDEX"

        def goship(self, msg, accepted, timestamp):
            """
            Define el protocolo de goship
            :param msg: Mensaje a enviar
            :param timestamp: Instante de emisión del mensaje
            :param accepted: ¿La función llamadora a aceptado el comando?
            :return: Se ha completado la operación?
            """
            if timestamp > time() or time() - timestamp > self.server.get_goship_timeout():
                # Expiran los datos o el timestamp es inválido
                return False
            if not accepted:
                if timestamp in self.server.accepted_comands:
                    if msg not in self.server.accepted_comands[timestamp]:
                        #  No lo ha aceptado y tampoco ha sido aceptado en el pasado. Se omite
                        return False
            else:
                # Si se ha aceptado el comando, lo guardamos
                # TODO Método para limpiar el diccionario(¿Sustituir por un árbol binario de búsqueda?)
                if timestamp not in self.server.accepted_comands:
                    self.server.accepted_comands[timestamp] = []
                if msg not in self.server.accepted_comands[timestamp]:
                    self.server.accepted_comands[timestamp].append(msg)
            nodes = [choice(self.server.nodes) for _ in range(self.server.goship_spanning)]
            for x in nodes:
                try:
                    # Esta operación es unidireccional, no necesitamos datos del otro peer
                    # Timeout 0 ya que necesitamos que se propague lo mas rápido posible
                    self.server.query_to(msg, *x, timeout=0)
                except (socket.error, BlockingIOError):
                    # Puede que el nodo nos haga un corte de manga, en tal caso no nos debemos enfadar
                    # TODO Método para detectar un nodo desconectado y echarlo de la lista de nodos
                    pass
            return True

        def recv(self, protocol_bytes=4, packet_size=1024*1024):
            """
            Recibe un mensaje del cliente
            :param protocol_bytes: Bytes que indican el tamaño del mensaje
            :param packet_size: Tamaño del paquete a leer
            :return: Paquete recibido
            """
            longitud = int.from_bytes(self.request.recv(protocol_bytes), "big")
            if longitud > self.server.max_message_length:
                raise MessageOverflow
            returneo = b""
            packet_num = int(ceil(longitud/packet_size))
            for _ in range(packet_num):
                returneo += self.request.recv(packet_size)
            return returneo

        def send(self, msg, protocol_bytes=4):
            """
            Envia un mensaje al cliente
            :param msg: Mensaje a enviar
            :param protocol_bytes: Bytes que indican el tamaño del mensaje
            :return: None
            """
            longitud = len(msg).to_bytes(protocol_bytes, "big")
            self.request.sendall(longitud+msg)

        # Notese que esta variable nos permite añadir comandos si extendemos la clase
        direccionamiento = {b"new_block": add_block, b"query_block": query_block, b"add_node": add_node,
                            b"register_node": register_node}

    allow_reuse_address = True  # En producción no debería de importar demasiado pero para testear viene bien

    def __init__(self, ip, port, chain=None):
        super().__init__((ip, port), self.HiloPeticion)
        self.ip = ip  # Ip del servidor
        self.port = port  # Puerto del servidor
        self.chain = chain  # Cadena de bloques
        if self.chain is None:
            self.chain = Blockchain()

        # Constantes
        self.max_message_length = 1024*1024*32  # 32 MiB
        self.client_timeout = 1  # Timeout del socket en cada petición
        self.goship_spanning = 2  # A cuantos nodos debo enviar la información en el protocolo de goship
        self.trial_add_node_on_register_timeout = 0.1

        # {timestamp: [comands]} Nos sirve para mantener enviando paquetes del protocolo
        # de goship aunque ahora no los aceptaramos(por ejemplo, 2 llamadas a add_block no darán el mismo resultado)
        self.accepted_comands = {}

        # Escuchamos peticiones hasta que se llame a self.shutdown()
        self.nodes = [(ip, port)]  # (ip, port)
        self.server_thread = Thread(target=self.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def add_block(self, block):
        """
        Añade un bloque a la blockchain. Extender para implementar funcionalidades
        :param block: Bloque a añadir
        :return: Successful?
        """
        if self.chain.add_block(block):
            return b"SUCCESS"
        else:
            return b"INVALID_BLOCK"

    def get_block(self, index):
        """
        Obtiene un bloque de la blockchain. Extender para implementar funcionalidades
        :param index: Index del bloque
        :return: Bloque solicitado
        :raise IndexError:
        """
        return self.chain[index]

    def append_node(self, addr):
        """
        Añade un nodo al servidor. Extender para implementar funcionalidades
        :param addr:
        :return:
        """
        if addr not in self.nodes:
            self.nodes.append(addr)
            return b"SUCCESS"
        return b"ALREADY_ADDED"

    def get_goship_timeout(self):
        """
        Obtiene el timeout del protocolo de goship. Extender en produccion
        :return: El tiempo que debe vivir un mensaje en el protocolo goship
        """
        return 0.2*len(self.nodes)

    @staticmethod
    def query_to(msg, ip, port, timeout=None, protocol_bytes=4):
        """
        Envia una petición al servidor
        :param msg: Mensaje a enviar
        :param ip: Dirección ip del servidor
        :param port: Puerto del servidor
        :param timeout: Tiempo de espera
        :param protocol_bytes: Bytes de protocolo
        :return: Respuesta del servidor
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((ip, port))
            sock.sendall(len(msg).to_bytes(protocol_bytes, "big")+msg)
            sock.settimeout(timeout)

            longitud = int.from_bytes(sock.recv(protocol_bytes), "big")
            returneo = sock.recv(longitud)
        return returneo
