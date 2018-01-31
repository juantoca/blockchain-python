from pickle import dumps

from library.blockchain_data_type import Blockchain, Block, restricted_loads


def mine(block, previous_hash, ceros=2):
    content = block.content.get_content()
    block.set_header(block.hash(previous_hash))
    if "nonce" not in content:
        content["nonce"] = 0
    while block.get_header()[:ceros] != "0"*ceros:
        content["nonce"] += 1
        block.content.set_content(content)
        block.set_header(block.hash(previous_hash))


class Node:

    def __init__(self, chain: Blockchain=None):
        self.chain:Blockchain = chain
        if self.chain is None:
            self.chain = Blockchain()

    def new_block(self, command: list) -> bytes:
        try:
            block: Block = restricted_loads(command[0])
        except Exception:
            return b"FORMAT_ERROR"
        if self.chain.add_block(block):
            return b"SUCCESS"
        else:
            return b"INVALID_BLOCK"

    def query_block(self, command: list) -> bytes:
        index = int.from_bytes(command[0], "big")
        try:
            return dumps(self.chain[index])
        except IndexError:
            return b"INDEX_ERROR"
