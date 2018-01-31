import unittest

import library.Crypt


class SignTest(unittest.TestCase):

    def test_sign(self):
        keys = library.Crypt.generate_rsa(4096)
        foreign_key = library.Crypt.generate_rsa(4096)
        msg = b"JORL"
        signed = library.Crypt.get_signature(msg, keys["PRIVATE"])
        forbidden = library.Crypt.get_signature(msg, foreign_key["PRIVATE"])
        self.assertEqual(library.Crypt.check_signature(msg, signed, keys["PUBLIC"]), True)
        self.assertEqual(library.Crypt.check_signature(msg, forbidden, keys["PUBLIC"]), False)


if __name__ == '__main__':
    unittest.main()
