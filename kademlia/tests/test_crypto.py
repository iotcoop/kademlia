import unittest

from kademlia.crypto import Crypto
from kademlia.domain.domain import PublicKey, PersistMode
from kademlia.utils import digest


class CryptoTests(unittest.TestCase):

    def setUp(self):
        self.crypto = Crypto()

    def test_get_signature(self):
        """
        get_signature should return signature for specified value and private key
        """
        priv_key = 'b22c8ea30609663197550b010e7abf5a9726523e8ca7ffdfb6a102815d3c8e97'
        tgs_sign = 'd83c0713135d774afda7df23e8c45d4456f0e7cfbea92824b8980d2d6934b16f5e7b665e95cfd7d7ec2eddcd9c5ca7e2c0e257df01817033bc0f2aab2ce7bab2'
        value_1 = b'test value'

        signature_1 = self.crypto.get_signature(value_1, priv_key).hex()
        self.assertEqual(signature_1, tgs_sign)

    def test_check_signature(self):
        """
        check_signature should validate signature
        """
        public_key = '0224d2079e86e937224f08aa37a857ca6116546868edde549d0bd6b8536af9d554'
        tcs_sig = '749625f8d70efae75ffd4a62e22c6534b2cbaa49212c454e6cfb7c5215e39ef01d0388999b2d38a24ad379245e1b4c69b9259b1c8c86bb011712999b4565192d'
        value = digest('some_key').hex() + 'some_data' + str(None) + str(PersistMode.SECURED)

        self.assertTrue(self.crypto.check_signature(digest(value), tcs_sig, public_key))


class PublicKeyTests(unittest.TestCase):

    def test__init__(self):
        """
        __init__ should set initial values for key and exp_time
        """
        public_key = PublicKey('test key')
        self.assertEqual(public_key.key, 'test key')
        self.assertIsNone(public_key.exp_time)
        public_key = PublicKey('test key', 123)
        self.assertEqual(public_key.exp_time, 123)

    def test_createKey_validFormat_ok(self):
        """
        key.set should check type and set key
        """
        public_key = PublicKey('test key')
        public_key.key = 'another key'
        self.assertEqual(public_key.key, 'another key')

    def test_createKey_invalidFormat_errorRaises(self):
        """
        key.set should check type and raise exception in case of invalid format
        """

        self.assertRaises(AssertionError, lambda: PublicKey(None))
        self.assertRaises(AssertionError, lambda: PublicKey(123))

    def test_of_json(self):
        """
        of_json should set key and exp_time from json
        """
        json = dict()
        json2 = dict()
        json['key'] = 'test key'
        json['exp_time'] = 123
        public_key = PublicKey.of_json(json)
        self.assertEqual(public_key.key, 'test key')
        self.assertEqual(public_key.exp_time, 123)
        self.assertRaises(AssertionError, lambda: PublicKey.of_json(json2))