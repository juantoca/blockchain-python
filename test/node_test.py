import unittest
from pickle import dumps
from library.blockchain_data_type import Block, restricted_loads
from nodo import Server
from time import sleep, time


class TestNodos(unittest.TestCase):

    def setUp(self):
        # Levantamos los nodos para realizar los tests
        self.nodes = []
        self.procesos = []
        for x in range(0, 20):
            self.nodes.append(Server("localhost", 8000+x))

    def tearDown(self):
        # Cerramos los sockets y matamos los procesos
        for x in range(0, len(self.nodes)):
            self.nodes[x].socket.close()
            self.nodes[x].shutdown()

    def test_command_validity(self):
        print("\nCOMMAND_FLOW_TEST")
        # No reconoce el comando
        self.assertEqual(Server.query_to(b"jorl", "localhost", 8000), b"INVALID_COMMAND")
        # Ha entrado en la función del comando
        self.assertEqual(Server.query_to(b"new_block", "localhost", 8000), b"FORMAT_ERROR")

    def test_add_block(self):
        print("\nADD_BLOCK_TEST")
        self.assertEqual(Server.query_to(b"new_block asnd", "localhost", 8000),
                         b"FORMAT_ERROR")  # Error en los parámetros
        self.assertEqual(Server.query_to(b"new_block "+dumps(Block()), "localhost", 8000),
                         b"INVALID_BLOCK")  # El bloque no tiene el hash correcto
        bloque = Block()
        bloque.set_header(bloque.hash(b""))
        self.assertEqual(Server.query_to(b"new_block "+dumps(bloque), "localhost", 8000),
                         b"SUCCESS")  # El bloque es correcto

    def test_query_block(self):
        print("\nQUERY_BLOCK_TEST")
        self.assertEqual(Server.query_to(b"query_block "+(10).to_bytes(1, "big"), "localhost", 8000),
                         b"INVALID_INDEX")  # Índice inválido
        query = restricted_loads(Server.query_to(b"query_block " + (0).to_bytes(1, "big"), "localhost", 8000))
        bloque = Block()
        bloque.timestamp = query.timestamp  # Es obvio que entonces el hash cambiaría pero es para hacer la comprobación
        self.assertEqual(str(query), str(bloque))  # Bloque genesis

    def test_add_node(self):
        print("\nADD_NODE_TEST")
        self.assertEqual(Server.query_to(b"add_node localhost 8001", "localhost", 8000), b"SUCCESS")
        self.assertEqual(Server.query_to(b"add_node kajfads", "localhost", 8000), b"INVALID_HOST")
        # Comprobamos el funcionamiento de la función ping
        self.assertEqual(Server.query_to(b"add_node localhost 8100", "localhost", 8000), b"INVALID_HOST")
        # Comprobamos que ha añadido el nodo correctamente
        self.assertEqual(self.nodes[0].nodes, [('localhost', 8000), ('localhost', 8001)])

    def test_register_node(self):
        print("\nREGISTER_NODE_TEST")
        for x in range(0, len(self.nodes)):
            Server.query_to(b"register_node " + bytes(str(int(time())), "ascii") +
                            b" localhost "+bytes(str(8000+x), "ascii"), "localhost", 8000)
        sleep(5)
        for x in range(0, len(self.nodes)):
            # Aqui no podemos usar asserts ya que, por como funciona goship, es un poco aleatorio
            # Porcentaje de acierto
            print("Porcentaje acierto "+str(x)+": "+str(len(self.nodes[x].nodes)/len(self.nodes)))

    def test_propagate_block(self):
        print("\nPROPAGATE_BLOCK_TEST")
        for x in self.nodes:
            x.nodes = [("localhost", 8000+x) for x in range(len(self.nodes))]
        bloque = Block()
        bloque.content.set_content("sdfna")
        bloque.set_header(bloque.hash(b""))
        self.assertEqual(Server.query_to(b"new_block " + dumps(bloque), "localhost", 8000),
                         b"SUCCESS")
        sleep(0.1)
        for x in self.nodes:
            print(x.chain)

    def test_protocol_data_size_limit(self):
        print("\nPROTOCOL_DATA_SIZE_LIMIT")
        Server.query_to(b"o"*1024*1024*32, "localhost", 8000)  # 32 megas


if __name__ == '__main__':
    unittest.main()
