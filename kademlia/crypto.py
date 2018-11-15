import logging

import hashlib
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

log = logging.getLogger(__name__)


class Crypto(object):

    @staticmethod
    def get_signature(value, priv_key, password=None):

        privkey = serialization.load_pem_private_key(
            priv_key, password=password, backend=default_backend())

        prehashed = bytes(hashlib.sha256(value).hexdigest(), 'ascii')

        sig = privkey.sign(
            prehashed,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())

        return sig

    @staticmethod
    def check_signature(value, signature, pub_key):

        decoded_key = base64.b64decode(pub_key)
        serialized_key = serialization.load_pem_public_key(decoded_key, backend=default_backend())
        decoded_sig = base64.b64decode(signature)

        prehashed_val = bytes(hashlib.sha256(value).hexdigest(), 'ascii')

        try:
            serialized_key.verify(
                decoded_sig,
                prehashed_val,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def signed_get_response(dkey, data, time=None, priv_key_path='key.pem', pub_key_path='public.pem'):
        from kademlia.utils import digest

        log.debug(f"Going to sign stored data with key: [{dkey.hex()}]")
        dval = digest(str(dkey) + str(data) + str(time))

        # computing signature and encoding in base64 using ascii encoding
        signature = str(base64.encodebytes(Crypto.get_signature(dval, open(priv_key_path).read().encode('ascii'))))[1:]

        # encoding node public key in base64 using ascii encoding
        pub_key = str(base64.b64encode(open(pub_key_path).read().encode('ascii')))[1:]
        log.debug(f"Successfully signed stored data with key: [{dkey.hex()}]")

        return {'value': data,
                'authorization': {
                    'pub_key': pub_key[1:-1],
                    'sign': signature.replace('\\n', '')[1:-1]
                }
                }
