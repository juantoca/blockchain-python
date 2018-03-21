import unittest
from library.blockchain_data_type import Block, Blockchain

class TestBlock(unittest.TestCase):

    def test_block_integrity(self):
        print("\n\nTEST: BLOCK_INTEGRITY")
        test_classes = [Block()]
        test_classes[-1].content.set_content("akndgña")
        test_classes.append(Block())
        test_classes[-1].set_header(
                test_classes[-1].hash(test_classes[-2].header))
        self.assertEqual(
                test_classes[-1].verify_block(test_classes[-2].header), True)
        # No hemos modificado nada en los bloques
        test_classes[-1].content.set_content("sñngadsf")
        # Al modificar algo en los bloques, es detectado por el test
        self.assertEqual(
                test_classes[-1].verify_block(test_classes[-2].header), False)

    def test_get_json(self):
        print("\n\nTEST: GET_JSON")
        block = Block()
        block.content.set_content({"content": "asdkjbfasd"})
        tmp = block.content.get_content()
        json = block.get_json()
        print(json)
        block.load_from_json(json)
        self.assertEqual(tmp, block.content.get_content())
        print(block)


class TestBlockchain(unittest.TestCase):

    def test_verify_chain(self):
        print("\n\nTEST: VERIFY_CHAIN")
        chain = Blockchain()
        for x in range(10):
            bloque = Block()
            bloque.set_header(bloque.hash(chain.get_last_hash()))
            chain.add_block(bloque)
        self.assertEqual(len(chain), 11)
        self.assertEqual(chain.validate_chain(), True)
        chain[5].content.set_content("ajñgna")
        print(str(chain))
        self.assertEqual(chain.validate_chain(blocks=(10, 10)), True)
        self.assertEqual(chain.validate_chain(blocks=(5, 5)), False)

    def test_chop(self):
        print("\n\nTEST: CHOP_CHAIN")
        chain = Blockchain()
        for x in range(10):
            bloque = Block()
            bloque.set_header(bloque.hash(chain.get_last_hash()))
            chain.add_block(bloque)
        self.assertEqual(len(chain), 11)
        chain.chop(5)
        self.assertEqual(len(chain), 5)


if __name__ == '__main__':
    unittest.main()
