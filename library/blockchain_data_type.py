from Crypto.Hash import SHA3_256
from json import dumps as dumps_json
from json import loads as loads_json
from pickle import dumps as dumps_pickle
from pickle import loads as loads_pickle
from copy import copy
import pickle
import io
import sys


class Content:

    def __init__(self, content=None):
        self.content = content
        if not self.content:
            self.content = {}

    def get_content(self):
        return self.content

    def set_content(self, content) -> None:
        self.content = content

    def hash(self):
        return SHA3_256.new(bytes(str(self.content), "utf-8")).hexdigest()

    def __str__(self) -> str:
        return str(self.content)

    def __len__(self):
        return len(self.content)


class Block:

    def __init__(self, index=0, content=None):
        self.index = index
        self.content = content
        if not self.content:
            self.content = Content()
        self.header = ""

    def set_header(self, header: str) -> None:
        """
        :param header: Actualiza la cabecera del bloque
        :return: None
        """
        self.header = header

    def get_header(self) -> str:
        """
        :return: Cabecera del bloque
        """
        return self.header

    def hash(self, previous_hash: str) -> str:
        """
        :param previous_hash: Hash del bloque anterior
        :return: Hash que debería tener la cabezera del bloque
        """
        return SHA3_256.new(bytes(previous_hash, "utf-8") + self.content.hash().encode("utf-8")).hexdigest()

    def verify_block(self, previous_hash) -> bool:
        """
        Verifica la integridad del bloque
        :param previous_hash: Hash del bloque anterior
        :return: Es el bloque integro?
        """
        if self.hash(previous_hash) == self.header:
            return True
        return False

    def set_index(self, i) -> None:
        self.index = i

    def __str__(self) -> str:
        return str({"id": self.index, "hash": self.header, "content": str(self.content)})

    def get_json(self):
        dic = copy(self.__dict__)
        dic["content"] = dumps_pickle(self.content).hex()  # Hay que serializarlo de algún modo
        return dumps_json(dic)

    def load_from_json(self, json):
        json = loads_json(json)
        self.content = loads_pickle(bytearray.fromhex(json["content"]))
        self.header = json["header"]


class Blockchain:

    def __init__(self, blocks=(Block(0), )):
        """
        Constructor de la blockchain
        :param blocks: Lista de bloques
        """
        self.blocks = list(blocks)

    def __len__(self) -> int:
        """
        :return: Longitud de la cadena
        """
        return len(self.blocks)

    def __getitem__(self, pos: int) -> Block:
        """
        :param pos: Index a obtener
        :return: Bloque en la posición indicada
        """
        return self.blocks[pos]

    def chop(self, i: int):
        """
        Eliminates blocks after the index selected
        :param i: index selected
        """
        self.blocks = self.blocks[:i]

    def validate_chain(self, blocks=None) -> bool:
        """
        Verifica la integridad de la cadena de bloques
        :param blocks: Intervalo de bloques a analizar, por defecto analiza toda la cadena
        :return: True si no hay incoherencias en la cadena, False si se han encontrado
        """
        if blocks is None:
            blocks = (1, len(self)-1)
        else:
            if len(blocks) != 2 or \
                            blocks[0] not in range(1, len(self)) or \
                            blocks[1] not in range(1, len(self)) or \
                            blocks[0] > blocks[1]:
                raise ValueError("Paramétro blocks inválido")
        for x in range(blocks[0], blocks[1]+1):
            if not self[x].verify_block(self[x-1].header):
                return False
        return True

    def add_block(self, block: Block) -> bool:
        """
        Añade un bloque a la cadena si el hash es coherente
        :param block: Bloque a añadir
        :return: Se ha añadido el bloque?
        """
        block.set_index(len(self))
        if block.verify_block(self.get_last_hash()):
            self.blocks.append(block)
            return True
        return False

    def get_last_hash(self):
        """
        Obtiene el hash del último bloque
        :return: String con el hash
        """
        return self[-1].get_header()

    def __str__(self):
        """
        :return: Representación en caracteres de la cadena
        """
        returneo = ""
        for x in self:
            returneo += str(x) + "\n"
        return returneo

class RestrictedUnpickler(pickle.Unpickler):

    """
    Clase que permite cargar objetos serializados de fuentes no confiables
    """

    allowed_classes = {"Block": Block, "Content": Content}

    def find_class(self, module, name):
        """
        :param module: Modulo al cual pertenece la clase a cargar
        :param name: Nombre de la clase a cargar
        :raises pickle.UnpicklingError: Tipo de clase inválido
        :return: Objeto cargado
        """
        try:
            cls = RestrictedUnpickler.allowed_classes[name]
        except KeyError:
            raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))
        if module == cls.__module__:
            return getattr(sys.modules[module], name)
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))

    def add_class(cls):
        """
        :param cls: Clase a registrar
        """
        RestrictedUnpickler.allowed_classes[cls.__name__] = cls

    def remove_class(cls):
        """
        :param cls: Clase a borrar
        """
        del RestrictedUnpickler.allowed_classes[cls.__name__]

def restricted_loads(s):
    """Helper function analogous to pickle.loads()."""
    return RestrictedUnpickler(io.BytesIO(s)).load()


