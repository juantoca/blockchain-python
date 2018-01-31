from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15


class InvalidKeySize(Exception):

    def __init__(self, *args):
        super().__init__(args)


def generate_block_size_rsa(public, passphrase=None):
    """
    Gets the size of each decryption block and maximum size for encryption blocks
    :param public: Public key to use for the checks
    :param passphrase: Passphrase for the key
    :return: (Size of decryption blocks, Maximum size for encryption blocks)
    """
    key = RSA.import_key(public, passphrase)
    return int((key.size_in_bits() - 384)/8 + 6)


def generate_rsa(bits, passphrase_public=None, passphrase_private=None):
    """
    Generate a pair of RSA keys
    :param bits: Bits of the key
    :param passphrase_public: Passphrase for the public key
    :param passphrase_private: Passphrase for the private key
    :return: {"PUBLIC":public key, "PRIVATE":private key}
    """
    if bits % 8 != 0 or bits < 1024:
        raise InvalidKeySize("The key must be a multiple of 8 and >= 1024")
    returneo = {"PUBLIC": None, "PRIVATE": None}
    key = RSA.generate(bits)
    returneo["PUBLIC"] = key.publickey().exportKey(passphrase=passphrase_public)
    returneo["PRIVATE"] = key.exportKey(passphrase=passphrase_private)
    return returneo


def encrypt_block_rsa(msg, key):
    """
    Encrypt plain-text block
    :param msg: Block to encrypt
    :param key: Public key(object not string) to use
    :return: Bits object representing the message encrypted
    """
    cipher_rsa = PKCS1_OAEP.new(key)
    msg = cipher_rsa.encrypt(msg)
    return msg


def encrypt_rsa(msg, public, max_block=None, passphrase=None):
    """
    Encrypts a given message
    :param msg: Message to encrypt(bytes or string)
    :param public: Public key to use
    :param max_block: Block size(use generate_block_size for a list of permitted block sizes)
    :param passphrase: Passphrase for the key
    :return: Bytes object representing the encrypted message
    """
    if max_block is None:
        max_block = generate_block_size_rsa(public, passphrase)
    if type(msg) == str:
        msg = msg.encode()
    key = RSA.import_key(public, passphrase)
    returneo = b""
    for x in range(0, len(msg), max_block):
        block = msg[x:x + max_block]
        returneo += encrypt_block_rsa(block, key)
    return returneo


def decrypt_block_rsa(msg, key):
    """
    Decrypt message
    :param msg: Bits object to decrypt
    :param key: Private key to use
    :return: Message's bytes
    """
    cipher_rsa = PKCS1_OAEP.new(key)
    msg = cipher_rsa.decrypt(msg)
    return msg


def decrypt_rsa(msg, private, passphrase=None):
    """
    Decrypt the given message
    :param msg: Bytes object to decrypt
    :param private: Private key to use
    :param passphrase: Passphrase for the key
    :return: Bytes object decrypted
    """
    key = RSA.import_key(private, passphrase)
    returneo = b""
    max_block = key.size_in_bytes()
    for x in range(0, len(msg), max_block):
        block = msg[x:x+max_block]
        returneo += decrypt_block_rsa(block, key)
    return returneo


def get_signature(msg: bytes, private:str, passphrase=None):
    """
    Gets the Signature of a given message
    :param msg: Bytes object to sign
    :param private: Private key to use
    :param passphrase: Passphrase for the key
    :return: Bytes object signature
    """
    key = RSA.importKey(private, passphrase)
    dig = SHA256.new(msg)
    return pkcs1_15.new(key).sign(dig)


def check_signature(msg: bytes, signature:bytes, public:str, passphrase=None):
    """
    Check if the Signature is valid
    :param msg: Bytes object signed
    :param signature:Signature to check
    :param public: Public key to use
    :param passphrase: Passphrase for the publickey
    """
    key = RSA.importKey(public, passphrase)
    dig = SHA256.new(msg)
    try:
        pkcs1_15.new(key).verify(dig, signature)
        return True
    except(ValueError, TypeError):
        return False


def generate_aes(key_size: int):
    if key_size not in (16, 24, 32):
        raise InvalidKeySize
    return get_random_bytes(key_size)


def encrypt_aes(txt, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(txt)
    return nonce + tag + ciphertext


def decrypt_aes(msg, key):
    nonce = msg[:16]
    tag = msg[16:32]
    cipher = msg[32:]
    key = AES.new(key, AES.MODE_EAX, nonce=nonce)
    returneo = key.decrypt(cipher)
    key.verify(tag)
    return returneo
