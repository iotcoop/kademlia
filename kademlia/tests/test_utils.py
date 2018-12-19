import hashlib
import unittest
from unittest.mock import Mock, patch

from kademlia.crypto import Crypto
from kademlia.domain.domain import PersistMode, is_new_value_valid, validate_authorization
from kademlia.exceptions import InvalidSignException, UnauthorizedOperationException
from kademlia.utils import digest, sharedPrefix, OrderedSet


class UtilsTest(unittest.TestCase):
    def test_digest(self):
        d = hashlib.sha1(b'1').digest()
        self.assertEqual(d, digest(1))

        d = hashlib.sha1(b'another').digest()
        self.assertEqual(d, digest('another'))

    def test_sharedPrefix(self):
        args = ['prefix', 'prefixasdf', 'prefix', 'prefixxxx']
        self.assertEqual(sharedPrefix(args), 'prefix')

        args = ['p', 'prefixasdf', 'prefix', 'prefixxxx']
        self.assertEqual(sharedPrefix(args), 'p')

        args = ['one', 'two']
        self.assertEqual(sharedPrefix(args), '')

        args = ['hi']
        self.assertEqual(sharedPrefix(args), 'hi')

    @patch('time.time', Mock(return_value=5))
    def test_validate_authorization(self):
        Crypto.check_signature = Mock(return_value=True)
        value = Mock()
        value.data = 'data'
        value.authorization.sign = 'sign'
        value.authorization.pub_key.exp_time = None
        value.authorization.pub_key.key = 'key'
        value.persist_mode = PersistMode.SECURED
        dkey = hashlib.sha1('key'.encode('utf8')).digest()
        dval = digest(dkey.hex() + value.data + str(value.authorization.pub_key.exp_time) + str(value.persist_mode))
        validate_authorization(dkey, value)
        Crypto.check_signature.assert_called_with(dval, 'sign', 'key')

        value.authorization.pub_key.exp_time = 6
        dval = digest(dkey.hex() + value.data + str(value.authorization.pub_key.exp_time) + str(value.persist_mode))
        validate_authorization(dkey, value)
        Crypto.check_signature.assert_called_with(dval, 'sign', 'key')

        value.authorization.pub_key.exp_time = 4
        with self.assertRaises(AssertionError):
            validate_authorization(hashlib.sha1('key'.encode('utf8')).digest(), value)

        value.authorization.pub_key.exp_time = 6
        Crypto.check_signature = Mock(return_value=False)
        with self.assertRaises(InvalidSignException):
            validate_authorization(hashlib.sha1('key'.encode('utf8')).digest(), value)

    @patch('kademlia.domain.domain.validate_authorization')
    def test_check_new_value_valid(self, mocked_va):
        stored_value = Mock()
        new_value = Mock()

        new_value.authorization = Mock()
        new_value.authorization.pub_key.key = '0224d2079e86e937224f08aa37a857ca6116546868edde549d0bd6b8536af9d554'
        stored_value.authorization = Mock()
        stored_value.authorization.pub_key.key = '0224d2079e86e937224f08aa37a857ca6116546868edde549d0bd6b8536af9d554'
        self.assertTrue(is_new_value_valid('dkey', stored_value, new_value))
        mocked_va.assert_called_with('dkey', new_value)

        new_value.authorization.pub_key.key = 'another key'

        self.assertFalse(is_new_value_valid('dkey', stored_value, new_value))

        new_value.authorization = None
        self.assertFalse(is_new_value_valid('dkey', stored_value, new_value))


class OrderedSetTest(unittest.TestCase):
    def test_order(self):
        o = OrderedSet()
        o.push('1')
        o.push('1')
        o.push('2')
        o.push('1')
        self.assertEqual(o, ['2', '1'])
