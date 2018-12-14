"""
Utility functions for tests.
"""
import random
import hashlib
from struct import pack

from kademlia.domain.domain import Value, PersistMode
from kademlia.node import Node
from kademlia.routing import RoutingTable


def mknode(node_id=None, ip=None, port=None, intid=None):
    """
    Make a node.  Created a random id if not specified.
    """
    if intid is not None:
        node_id = pack('>l', intid)
    if not node_id:
        randbits = str(random.getrandbits(255))
        node_id = hashlib.sha1(randbits.encode()).digest()
    return Node(node_id, ip, port)


class FakeProtocol:
    def __init__(self, sourceID, ksize=20):
        self.router = RoutingTable(self, ksize, Node(sourceID))
        self.storage = {}
        self.sourceID = sourceID


def get_signed_value_with_keys(priv_key_path, pub_key_path):

        def get_signed_value(dkey, value, persist_mode):
            return Value.of_params(dkey, value, persist_mode, None, priv_key_path, pub_key_path)

        return get_signed_value
