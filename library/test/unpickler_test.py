import os
import unittest
from _pickle import UnpicklingError
from pickle import dumps

from library.blockchain_data_type import Block, restricted_loads, RestrictedUnpickler


class TestPickle(unittest.TestCase):

    def test_pickle_security(self):
        print("\nTEST: RESTRICTED_UNPICKLER")
        forbiden = [dumps(eval), dumps(print), dumps(os.chmod)]
        allowed = dumps(Block())
        for x in forbiden:
            with self.assertRaises(UnpicklingError):
                restricted_loads(x) # Comprobamos que no cargue nada indebido
        self.assertEqual(str(restricted_loads(allowed)), "{'id': 0, 'hash': '', 'content': '{}'}") # Comprobamos que carga lo debido
        RestrictedUnpickler.add_class(eval)
        self.assertEqual(restricted_loads(dumps(eval)), eval) # Comprobamos que añade bien las clases
        RestrictedUnpickler.remove_class(eval)
        with self.assertRaises(UnpicklingError): # Comprobamos que borra bien las clases
            restricted_loads(dumps(eval))


if __name__ == '__main__':
    unittest.main()
