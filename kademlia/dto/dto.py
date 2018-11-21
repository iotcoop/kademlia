import logging

from kademlia.config import Config
from kademlia.crypto import Crypto
from kademlia.exceptions import InvalidValueFormatException

log = logging.getLogger(__name__)


class JsonSerializable(object):

    def to_dict(self):
        json_dict = {}
        for k, v in self.__dict__.items():
            if '__' not in k:
                # Remove `_` from field name
                k = k[1:]
                if isinstance(v, JsonSerializable):
                    json_dict[k] = v.to_dict()
                elif v is None or type(v) in [str, int, bool, dict, list]:
                    json_dict[k] = v
                else:
                    json_dict[k] = str(v)

        return json_dict


class PublicKey(JsonSerializable):

    def __init__(self, base64_pub_key, exp_time=None):
        self.key = base64_pub_key
        self.exp_time = exp_time

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, base64_pub_key):
        check_pkey_type(base64_pub_key)
        self._key = base64_pub_key

    @property
    def exp_time(self):
        return self._exp_time

    @exp_time.setter
    def exp_time(self, exp_time):
        self._exp_time = exp_time

    @staticmethod
    def of_json(dct):
        assert 'exp_time' in dct
        assert 'key' in dct

        return PublicKey(dct['key'], dct['exp_time'])


class Authorization(JsonSerializable):

    def __init__(self, pub_key: PublicKey, sign):
        self.sign = sign
        self.pub_key = pub_key


    @property
    def pub_key(self):
        return self._pub_key

    @pub_key.setter
    def pub_key(self, value):
        self._pub_key = value

    @property
    def sign(self):
        return self._sign

    @sign.setter
    def sign(self, value):
        self._sign = value

    @staticmethod
    def of_json(dct):
        assert 'pub_key' in dct
        assert 'sign' in dct

        return Authorization(PublicKey.of_json(dct['pub_key']), dct['sign'])


class Value(JsonSerializable):

    def __init__(self, data, authorization: Authorization):
        assert type(authorization) is Authorization

        self.authorization = authorization
        self.data = data

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        if check_dht_value_type(value):
            self._data = value
        else:
            raise TypeError("Value must be of type int, float, bool, str, or bytes")

    @property
    def authorization(self):
        return self._authorization

    @authorization.setter
    def authorization(self, authorization):
        assert type(authorization) is Authorization or \
               authorization is None
        self._authorization = authorization

    @staticmethod
    def of_json(dct):
        assert 'authorization' in dct
        assert 'data' in dct

        if dct['authorization'] is None:
            raise InvalidValueFormatException('Invalid value format, value should contain authorization')
        else:
            return Value(dct['data'], Authorization.of_json(dct['authorization']))

    @staticmethod
    def get_signed(dkey, data, time=None, priv_key_path=Config.PRIVATE_KEY_PATH, pub_key_path=Config.PUBLIC_KEY_PATH):
        import base64
        from kademlia.utils import digest

        log.debug(f"Going to sign {data} with key: [{dkey.hex()}]")
        dval = digest(str(dkey) + str(data) + str(time))
        signature = str(base64.encodebytes(Crypto.get_signature(dval, open(priv_key_path).read().encode('ascii'))))[1:]
        pub_key = str(base64.b64encode(open(pub_key_path).read().encode('ascii')))[1:]
        log.debug(f"Successfully signed data with key: [{dkey.hex()}]")

        return Value(data, Authorization(PublicKey(pub_key, time), signature.replace('\\n', '')))


def check_dht_value_type(value):
    """
    Checks to see if the type of the value is a valid type for
    placing in the dht.
    """
    typeset = {int, float, bool, str, bytes}
    return type(value) in typeset or value is None


def check_pkey_type(base64_pub_key):
    assert type(base64_pub_key) is str
