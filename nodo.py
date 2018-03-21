from pickle import dumps, UnpicklingError
import socket
from library.blockchain_data_type import Blockchain, Block, restricted_loads
import socketserver

# Aunque estemos sujetos al GIL, como la mayoría de operaciones son de I/O(red y accesos a disco),
# no afectaría al rendimiento (incluso sería contraproducente) lanzar procesos del sistema con multiproccesing
from threading import Thread, Lock

from math import ceil
from time import time
from random import choice
from Crypto.Hash import SHA3_256
# Sin embargo, para cosas como la minería debemos liberar cpu para que no colapse el proceso principal
from multiprocessing import Process
from multiprocessing import Manager


class MessageOverflow(Exception):

    pass


def mine_msg(msg: bytes, zeros: int, timestamp: bytes):
    """
    Nos mina un mensaje para que supere la PoW del nodo
    :param msg: Mensaje a minar
    :param zeros: Dificultad del PoW
    :param timestamp: b"" si el mensaje no contiene timestamp, el timestamp si lo contiene
    :return: Mensaje minado
    """
    m = Manager()
    var_return = m.Value(bytes, b"")

    def helper(msg, zeros, var_return, timestamp: bytes) -> None:
        h = b"1"
        counter = 0
        if not timestamp:
            msg = [msg]
        else:
            msg = msg.split(timestamp, 1)
        returneo = bytes(str(counter), "ascii") + b" " + timestamp.join(msg)
        while not check_msg_pow(returneo, zeros):
            returneo = bytes(str(counter), "ascii") + b" " + bytes(str(int(time())), "ascii").join(msg)
            counter += 1
        var_return.value = returneo

    p = Process(target=helper, args=(msg, zeros, var_return, timestamp))
    #  Debemos liberar CPU para atender bien las peticiones de I/O. Por ello usamos Proccess
    # (lanzamos proceso de sistema para asi liberar presión sobre el hilo de ejecución de los Threads)
    p.start()
    p.join()
    return var_return.value


def check_msg_pow(msg: bytes, zeros: int) -> bool:
    """
    Comprobamos que un mensaje cumple el PoW
    :param msg: Mensaje a comprobar
    :param zeros: Dificultad de la PoW
    :return: ¿Ha pasado la prueba?
    """
    h = SHA3_256.new(msg).digest()
    n = int.from_bytes(h, "big")
    return n >> 256 - zeros == 0


class HiloPeticion(socketserver.BaseRequestHandler):

        """
        Esta clase definirá todo el protocolo de comunicación. Parseará los comandos recibidos y
        ejecutará las funciones correspondientes sobre la blockchain
        """

        def handle(self):
            """
            Interfaz que redirecciona los comandos a su correspondiente función
            """
            self.request.settimeout(self.server.client_timeout)
            try:
                msg = self.recv()
                if not check_msg_pow(msg, self.server.get_protocol_pow()):  # Comprobamos la prueba de trabajo
                    self.send(b"INVALID_POW")
                    return
                command = msg.split(b" ", 1)[1].split(b" ", 1)  # [opcode, args]
                if len(command) == 1:
                    command.append(b"")
                if command[0] in self.direccionamiento:
                    # Llamamos al comando correspondiente
                    self.send(self.direccionamiento[command[0]](self, command[1], msg))
                else:
                    self.send(b"INVALID_COMMAND")  # Notificamos que no reconocemos el comando
            except socket.timeout:
                self.send(b"TIMED_OUT")
            except MessageOverflow:
                self.send(b"MESSAGE_OVERFLOW")
            except socket.error:
                pass

        def register_node(self, args: bytes, msg: bytes) -> bytes:
            """
            Protocolo para registrar un nodo en la red
            :param args: (pow) (ip) (puerto)
            :param msg: Mensaje original
            :return: Bytes de estado
            """
            comando = args.split(b" ")
            if not check_msg_pow(args, self.server.get_register_pow()):
                return b"POW_ERROR"
            if len(comando) != 4:
                return b"FORMAT_ERROR"
            try:
                timestamp = int(comando[1])
                ip = str(comando[2], "ascii")
                port = int(str(comando[3], "ascii"))
            except ValueError:
                return b"FORMAT_ERROR"
            if self.add_node(b" ".join(comando[2:]), msg) == b"SUCCESS":
                self.goship(msg, True, timestamp)  # Propagamos la petición de registro
                salir = time()
                while salir > time() - self.server.get_trial_add_node_on_register_timeout():
                    try:
                        # Intentamos notificar al nuevo nodo de nuestra existencia
                        self.server.query_to(b"add_node "+bytes(self.server.ip, "ascii")+b" " +
                                             bytes(str(self.server.port), "ascii"), ip, port,
                                             timeout=self.server.get_trial_add_node_on_register_timeout())
                        salir = 0
                    except (socket.error, BlockingIOError):
                        pass
            else:
                # Propagamos la petición de registro
                self.goship(msg, False, timestamp)
            return b"SUCCESS"

        def add_block(self, args: bytes, msg: bytes) -> bytes:
            """
            Protocolo para añadir un bloque a la blockchain
            :param args: Bloque a añadir
            :param msg: Mensaje original
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
                self.goship(msg, True, block.timestamp)
            else:
                self.goship(msg, False, block.timestamp)
            return result

        def ping(self, ip: str, port: int) -> bool:
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

        def add_node(self, args: bytes, msg: bytes) -> bytes:
            """
            Añade un nodo a la lista local de nodos
            :param args: (pow) (ip) (port)
            :param msg: Mensaje original
            :return: Bytes de estado
            """
            addr = args.split(b" ")
            try:
                addr = (str(addr[0], "ascii"), int(addr[1]))
                if len(addr) == 2 and self.ping(*addr):
                    return self.server.append_node(addr)
                raise ValueError
            except (ValueError, IndexError):
                return b"INVALID_HOST"

        def query_block(self, args: bytes, msg: bytes) -> bytes:
            """
            Protocolo de solicitud de bloque
            :param args: bytes(index del comando)
            :param msg: Mensaje original
            :return: dumps(bloque) o bytes("INVALID INDEX")
            """
            index = int.from_bytes(args, "big")
            try:
                return dumps(self.server.get_block(index))
            except IndexError:
                return b"INVALID_INDEX"

        def goship(self, msg: bytes, accepted: bool, timestamp: int) -> bool:
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
                self.server.add_goship(timestamp, msg)
            nodes = [choice(self.server.nodes) for _ in range(self.server.get_goship_spanning())]
            for x in nodes:
                try:
                    # Esta operación es unidireccional, no necesitamos datos del otro peer
                    # Timeout bajo ya que necesitamos que se propague lo mas rápido posible
                    self.server.query_to(msg, *x, timeout=0, mine=False)
                except (socket.error, BlockingIOError):
                    # Puede que el nodo nos haga un corte de manga, en tal caso no nos debemos enfadar
                    # TODO Método para detectar un nodo desconectado y echarlo de la lista de nodos.
                    # ¿Sistema de prioridad en base a la disponibilidad pasada?
                    pass
            return True

        def recv(self, protocol_bytes: int=4, packet_size: int=1024*1024) -> bytes:
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

        def send(self, msg: bytes, protocol_bytes: int=4) -> None:
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


class Server(socketserver.ThreadingTCPServer):

    """
    Clase que se encarga de soportar todo el protocolo de comunicación haciendo de intérprete entre la blockchain y la
    red. La idea es que en producción se extienda para añadir las especificaciones del caso de uso de la blockchain
    """

    allow_reuse_address = True  # En producción no debería de importar demasiado pero para testear viene bien
    peticiones = HiloPeticion

    def __init__(self, ip: str, port: int, chain: Blockchain=None):
        super().__init__((ip, port), Server.peticiones)
        self.ip = ip  # Ip del servidor
        self.port = port  # Puerto del servidor
        self.chain = chain  # Cadena de bloques
        if self.chain is None:
            self.chain = Blockchain()

        # Constantes
        self.max_message_length = 1024*1024*64  # 64 MiB
        self.client_timeout = 1  # Timeout del socket en cada petición
        self.goship_spanning = 2  # A cuantos nodos debo enviar la información en el protocolo de goship

        # Cuanto tiempo debo intentar añadirme a mi mismo cuando hay una llamada a register_node
        self.trial_add_node_on_register_timeout = 3

        # Prueba de trabajo base para todos los mensajes (Cambiar en producción)
        self.protocol_pow = 17

        # Como es lógico, propagar el registro de un nodo no benigno es contraproducente,
        # por lo que hay que endurecer el coste de entrada a la red (Cambiar en producción)
        self.register_pow = 20

        # {timestamp: [comands]} Nos sirve para mantener enviando paquetes del protocolo
        # de goship aunque ahora no los aceptaramos(por ejemplo, 2 llamadas a add_block no darán el mismo resultado)
        self.accepted_comands = {}
        self.accepted_comands_lock = Lock()

        # Escuchamos peticiones hasta que se llame a self.shutdown()
        self.nodes = [(ip, port)]  # (ip, port)
        self.server_thread = Thread(target=self.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def add_goship(self, timestamp, msg):
        """
        Añade un mensaje de goship aceptado a la caché
        :param timestamp: Tiempo original del mensaje
        :param msg: Mensaje de goship
        """

        def clean_goship():
            claves = []
            timeout = self.get_goship_timeout()
            tiempo = time()
            for x in self.accepted_comands.keys():
                if tiempo - x > timeout:
                    claves.append(x)
            for x in claves:
                del self.accepted_comands[x]

        with self.accepted_comands_lock:
            if timestamp not in self.accepted_comands:
                self.accepted_comands[timestamp] = []
            if msg not in self.accepted_comands[timestamp]:
                self.accepted_comands[timestamp].append(msg)
            clean_goship()

    def add_block(self, block: Block) -> bytes:
        """
        Añade un bloque a la blockchain. Extender para implementar funcionalidades
        :param block: Bloque a añadir
        :return: Successful?
        """
        if self.chain.add_block(block):
            return b"SUCCESS"
        else:
            return b"INVALID_BLOCK"

    def get_block(self, index: int) -> Block:
        """
        Obtiene un bloque de la blockchain. Extender para implementar funcionalidades
        :param index: Index del bloque
        :return: Bloque solicitado
        :raise IndexError: Bloque inválido
        """
        return self.chain[index]

    def append_node(self, addr: tuple) -> bytes:
        """
        Añade un nodo al servidor. Extender para implementar funcionalidades
        :param addr: Direccion del nodo
        :return: Bytes de estado
        """
        if addr not in self.nodes:
            self.nodes.append(addr)
            return b"SUCCESS"
        return b"ALREADY_ADDED"

    def get_goship_timeout(self) -> float:
        """
        Obtiene el timeout del protocolo de goship. Extender en produccion
        :return: El tiempo que debe vivir un mensaje en el protocolo goship
        """
        return 0.2*len(self.nodes)

    def get_goship_spanning(self):
        return self.goship_spanning

    def get_protocol_pow(self):
        return self.protocol_pow

    def get_register_pow(self):
        return self.register_pow

    def get_trial_add_node_on_register_timeout(self):
        return self.trial_add_node_on_register_timeout

    def get_client_timeout(self):
        return self.client_timeout

    def query_to(self, msg: bytes, ip: str, port: int, timeout: int=None, protocol_bytes: int=4,
                 mine: bool=True, timestamp: bytes= b"") -> bytes:
        """
        Envia una petición al servidor
        :param msg: Mensaje a enviar
        :param ip: Dirección ip del servidor
        :param port: Puerto del servidor
        :param timeout: Tiempo de espera
        :param protocol_bytes: Bytes de protocolo
        :param mine: ¿Hay que minar el mensaje?
        :param timestamp: Timestamp para el minero
        :return: Respuesta del servidor
        """
        if mine:
            msg = mine_msg(msg, self.protocol_pow, timestamp)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((ip, port))
            sock.sendall(len(msg).to_bytes(protocol_bytes, "big")+msg)
            sock.settimeout(timeout)

            longitud = int.from_bytes(sock.recv(protocol_bytes), "big")
            returneo = sock.recv(longitud)
        return returneo
