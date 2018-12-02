import logging

from secp256k1 import PrivateKey, PublicKey

log = logging.getLogger(__name__)


class Crypto(object):

    @staticmethod
    def get_signature(message: bytes, priv_key: str):
        priv_key = PrivateKey(priv_key, raw=False)

        sig = priv_key.ecdsa_sign(message)
        return priv_key.ecdsa_serialize(sig)

    @staticmethod
    def check_signature(message: bytes, signature: str, pub_key: str):
        privkey = PrivateKey()
        pub_key = PublicKey(bytes(bytearray.fromhex(pub_key)), raw=True)

        sig = privkey.ecdsa_deserialize(bytes(bytearray.fromhex(signature)))

        return pub_key.ecdsa_verify(message, sig)

