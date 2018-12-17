import logging

from secp256k1 import PrivateKey, PublicKey

log = logging.getLogger(__name__)


class Crypto(object):

    @staticmethod
    def get_signature(message: bytes, priv_key: str):
        priv_key = PrivateKey(priv_key, raw=False)

        sig = priv_key.ecdsa_sign(message)
        return priv_key.ecdsa_serialize_compact(sig)

    @staticmethod
    def check_signature(message: bytes, signature: str, pub_key: str):
        try:
            pub_key = PublicKey(bytes(bytearray.fromhex(pub_key)), raw=True)
            sig = pub_key.ecdsa_deserialize_compact(bytes(bytearray.fromhex(signature)))
            return pub_key.ecdsa_verify(message, sig)
        except Exception as ex:
            log.exception(ex)
            return False

