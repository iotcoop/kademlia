"""
General catchall for functions that don't make sense as methods.
"""
import hashlib
import logging
import operator
import asyncio
from functools import partial

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


def get_field(field_name: str):
    def get_from(value: dict) -> str:
        return value.get(field_name) if value else None

    return get_from


def compose(inner, outer):
    def composed(*args, **kwargs):
        return outer(inner(*args, **kwargs))
    return composed


def unpack(data: str) -> dict:
    import json
    result = None
    try:
        result = json.loads(data)
    finally:
        return result


def filtering_by(reference_type):
    return partial(filter, lambda it: type(it) is reference_type)