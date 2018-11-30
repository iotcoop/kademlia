import logging
from enum import Enum

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
                elif isinstance(v, PersistMode):
                    json_dict[k] = v.value
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


class PersistMode(Enum):
    SECURED = 'SECURED'
    CONTROLLED = 'CONTROLLED'

    def __str__(self):
        return str(self.value)


class Value(JsonSerializable):

    def __init__(self, data, persist_mode, authorization: Authorization):
        self.authorization = authorization
        self.data = data
        self.persist_mode = persist_mode

    def __str__(self):
        import json
        return json.dumps(self.to_dict())

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, data):
        if isinstance(data, str) or data is None:
            self._data = data
        else:
            raise TypeError("Value must be of type int, float, bool, str, or bytes")

    @property
    def persist_mode(self):
        return self._persist_mode

    @persist_mode.setter
    def persist_mode(self, persist_mode):
        if persist_mode in (m.value for m in PersistMode):
            self._persist_mode = PersistMode(persist_mode)
        else:
            raise TypeError("Value persist mode MUST be 'SECURED' or 'CONTROLLED'")

    @property
    def authorization(self):
        return self._authorization

    @authorization.setter
    def authorization(self, authorization):
        assert type(authorization) is Authorization or \
               authorization is None
        self._authorization = authorization

    @staticmethod
    def of_json(dct: dict):
        check_value_json(dct)
        return Value(dct['data'], dct['persist_mode'], Authorization.of_json(dct['authorization']))

    @staticmethod
    def of_string(string: str):
        import json
        dct = json.loads(string)
        return Value.of_json(dct)


    @staticmethod
    def get_signed(dkey, data, persist_mode=PersistMode.SECURED, time=None, priv_key_path=Config.PRIVATE_KEY_PATH,
                   pub_key_path=Config.PUBLIC_KEY_PATH):
        import base64
        from kademlia.utils import digest

        log.debug(f"Going to sign {data} with key: [{dkey.hex()}]")

        dval = digest(dkey.hex() + str(data) + str(time) + str(persist_mode))
        with open(priv_key_path) as priv_key:
            signature = str(base64.encodebytes(Crypto.get_signature(dval, priv_key.read().encode('ascii'))))[1:]
        with open(pub_key_path) as pub_key:
            pub_key = str(base64.b64encode(pub_key.read().encode('ascii')))[1:]
        log.debug(f"Successfully signed data with key: [{dkey.hex()}]")

        return Value(data, str(persist_mode), Authorization(PublicKey(pub_key, time), signature.replace('\\n', '')))


def check_value_json(dct: dict):
    auth = dct.get('authorization')
    p_mode = dct.get('persist_mode')
    data = dct.get('data')

    if not all((auth, p_mode, data)):
        raise InvalidValueFormatException(
            'Invalid value format, value MUST contain following keys: authorization, persist_mode, data')

    if p_mode not in (m.value for m in PersistMode):
        raise InvalidValueFormatException('Invalid value format, persist_mode MUST be set to "SECURED" or "CONTROLLED"')


def check_pkey_type(base64_pub_key):
    assert type(base64_pub_key) is str
