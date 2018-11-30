"""
General catchall for functions that don't make sense as methods.
"""
import hashlib
import logging
import operator
import asyncio
import time

from kademlia.crypto import Crypto
from kademlia.dto.dto import Value, PersistMode
from kademlia.exceptions import InvalidSignException, UnauthorizedOperationException

log = logging.getLogger(__name__)


async def gather_dict(d):
    cors = list(d.values())
    results = await asyncio.gather(*cors)
    return dict(zip(d.keys(), results))


def digest(s):
    if not isinstance(s, bytes):
        s = str(s).encode('utf8')
    return hashlib.sha1(s).digest()


class OrderedSet(list):
    """
    Acts like a list in all ways, except in the behavior of the
    :meth:`push` method.
    """

    def push(self, thing):
        """
        1. If the item exists in the list, it's removed
        2. The item is pushed to the end of the list
        """
        if thing in self:
            self.remove(thing)
        self.append(thing)


def sharedPrefix(args):
    """
    Find the shared prefix between the strings.

    For instance:

        sharedPrefix(['blahblah', 'blahwhat'])

    returns 'blah'.
    """
    i = 0
    while i < min(map(len, args)):
        if len(set(map(operator.itemgetter(i), args))) != 1:
            break
        i += 1
    return args[0][:i]


def bytesToBitString(bites):
    bits = [bin(bite)[2:].rjust(8, '0') for bite in bites]
    return "".join(bits)


# TODO: move to value responsibilities
def validate_secure_value(dkey, new_value: Value, stored_value: dict):
    if new_value.persist_mode != PersistMode.SECURED:
        raise UnauthorizedOperationException()
    stored_value = Value.of_json(stored_value)
    if new_value.persist_mode != stored_value.persist_mode:
        raise UnauthorizedOperationException()
    check_new_value_valid(dkey, stored_value, new_value)


# TODO: move to value responsibilities
def validate_controlled_value(dkey, new_value, stored_value: list):
    if new_value.persist_mode != PersistMode.CONTROLLED:
        raise UnauthorizedOperationException()
    controlled_value = {}
    nv_pub_key = new_value.authorization.pub_key.key
    for val in stored_value:
        controlled_value[val['authorization']['pub_key']['key']] = Value.of_json(val)
    if nv_pub_key in controlled_value.keys():
        check_new_value_valid(dkey, controlled_value.get(nv_pub_key), new_value)


def validate_authorization(dkey, value: Value):
    log.debug(f"Going to validate authorization for key {dkey.hex()}")
    sign = value.authorization.sign
    exp_time = value.authorization.pub_key.exp_time
    persist_mode = value.persist_mode
    data = value.data
    assert exp_time is None or exp_time > int(time.time())

    d_record = digest(dkey.hex() + str(data) + str(exp_time) + persist_mode.value)

    if not Crypto.check_signature(d_record, sign, value.authorization.pub_key.key):
        raise InvalidSignException(sign)


#TODO: only authorized values supported, remove redundant logical branches
def check_new_value_valid(dkey, stored_value: Value, new_value: Value):

    if stored_value.authorization is None and new_value.authorization is None:
        return True
    elif stored_value.authorization is None and new_value.authorization is not None:
        validate_authorization(dkey, new_value)
        return True
    elif stored_value.authorization is not None and new_value.authorization is not None:
        validate_authorization(dkey, new_value)
        if stored_value.authorization.pub_key.key == new_value.authorization.pub_key.key:
            return True
        else:
            raise UnauthorizedOperationException
    else:
        raise UnauthorizedOperationException


def select_most_common_response(responses):
    from collections import Counter

    if responses:
        if not isinstance(responses, list):
            responses = [responses]

        values = [r['data'] for r in responses]
        value_counts = Counter(values)

        return value_counts.most_common(1)[0][0]
    else:
        return None
