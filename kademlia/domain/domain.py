import json
import logging
import time
from collections import defaultdict
from copy import deepcopy
from enum import Enum
from functools import partial
from itertools import chain

from kademlia.config import Config
from kademlia.crypto import Crypto
from kademlia.exceptions import InvalidValueFormatException, UnauthorizedOperationException, InvalidSignException
from kademlia.utils import digest, compose, get_field, unpack, filtering_by

log = logging.getLogger(__name__)


class JsonSerializable(object):

    def to_json(self):
        json_dict = {}
        for k, v in self.__dict__.items():
            if '__' not in k:
                # Remove `_` from field name
                k = k[1:]
                if isinstance(v, JsonSerializable):
                    json_dict[k] = v.to_json()
                elif v is None or type(v) in [str, int, bool, dict, list]:
                    json_dict[k] = v
                elif isinstance(v, PersistMode):
                    json_dict[k] = v.value
                else:
                    json_dict[k] = str(v)

        return json_dict


class PublicKey(JsonSerializable):

    def __init__(self, hex_pub_key, exp_time=None):
        self.key = hex_pub_key
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

    def __init__(self, dkey: bytes, data: str, persist_mode: str, authorization: Authorization):
        self.__dkey = dkey
        self.authorization = authorization
        self.data = data
        self.persist_mode = persist_mode

    def __str__(self):
        return json.dumps(self.to_json())

    def __eq__(self, other):
        return self.to_json() == other.to_json()

    def __hash__(self):
        dval = digest(self.__dkey.hex() + self.data + str(self.authorization.pub_key.exp_time) + str(self.persist_mode))
        return int(dval.hex(), 16)

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, data):
        if isinstance(data, str) or data is None:
            self._data = data
        else:
            raise TypeError('Value must be of type int, float, bool, str, or bytes')

    @property
    def key(self):
        return self.__dkey

    @property
    def persist_mode(self):
        return self._persist_mode

    @persist_mode.setter
    def persist_mode(self, persist_mode):
        if persist_mode in (m.value for m in PersistMode):
            self._persist_mode = PersistMode(persist_mode)
        else:
            raise TypeError('Value persist mode MUST be "SECURED" or "CONTROLLED"')

    @property
    def authorization(self):
        return self._authorization

    @authorization.setter
    def authorization(self, authorization):
        assert type(authorization) is Authorization or \
               authorization is None
        self._authorization = authorization

    def is_valid(self):
        dval = digest(self.__dkey.hex() + self.data + str(self.authorization.pub_key.exp_time) + str(self.persist_mode))
        return Crypto.check_signature(dval, self.authorization.sign, self.authorization.pub_key.key)

    @staticmethod
    def of_json(key: bytes, dct: dict):
        check_value_json(dct)
        return Value(key, dct['data'], dct['persist_mode'], Authorization.of_json(dct['authorization']))

    @staticmethod
    def of_string(key: bytes, string: str):
        dct = json.loads(string)
        return Value.of_json(key, dct)

    @staticmethod
    def of_params(dkey: bytes, data: str, persist_mode: PersistMode, time=None, priv_key_path=Config.PRIVATE_KEY_PATH,
                  pub_key_path=Config.PUBLIC_KEY_PATH):
        log.debug(f'Going to sign {data} with key: [{dkey.hex()}]')

        dval = digest(dkey.hex() + str(data) + str(time) + str(persist_mode))
        with open(priv_key_path) as priv_key:
            signature = Crypto.get_signature(dval, priv_key.read()).hex()
        with open(pub_key_path) as pub_key:
            pub_key = pub_key.read()
        log.debug(f'Successfully signed data with key: [{dkey.hex()}]')

        return Value(dkey, data, str(persist_mode), Authorization(PublicKey(pub_key, time), signature))


class ControlledValue(JsonSerializable):

    def __init__(self, dkey: bytes, values: list):
        self.__dkey = dkey
        self._values = {val.authorization.pub_key.key: val for val in values}

    def __str__(self):
        return json.dumps([val.to_json() for val in self.values])

    def to_json(self):
        return [val.to_json() for val in self.values]

    @property
    def values(self):
        return self._values.values()

    @values.setter
    def values(self, values):
        if all(map(lambda it: type(it) is Value and it.persist_mode is PersistMode.CONTROLLED, values)):
            self._values = {val.authorization.pub_key.key: val for val in values}
        else:
            raise TypeError('All values must be of type Value and persist mode CONTROLLED')

    @classmethod
    def empty(cls, dkey: bytes):
        return cls(dkey, list())

    # TODO: add creation time to value
    def add_value(self, value: Value):
        assert value.persist_mode is PersistMode.CONTROLLED and value.is_valid()
        n_pub_key = value.authorization.pub_key.key

        if n_pub_key in self._values.keys() and not is_new_value_valid(self.__dkey, self._values.get(n_pub_key), value):
            raise UnauthorizedOperationException()

        self._values[n_pub_key] = value

        return deepcopy(self)

    def is_valid(self):
        return all(map(lambda value: value.is_valid and value.persist_mode is PersistMode.CONTROLLED, self.values))

    @classmethod
    def of_json(cls, dkey: bytes, jsn: list):
        values = [Value.of_json(dkey, val_jsn) for val_jsn in jsn]
        if all(map(lambda it: it.persist_mode is PersistMode.CONTROLLED and it.is_valid(), values)):
            return ControlledValue(dkey, values)
        else:
            raise ValueError('All json values must have persist mode "CONTROLLED"')

    @staticmethod
    def of_string(dkey: bytes, json_string: str):
        return ControlledValue.of_json(dkey, json.loads(json_string))

    def merge(self, controller_value):
        if controller_value.is_valid():
            for value in controller_value:
                self.add_value(value)


class ValueFactory(object):

    @staticmethod
    def create_from_json(dkey, jsn):
        if isinstance(jsn, list):
            return ControlledValue.of_json(dkey, jsn)
        else:
            value = Value.of_json(dkey, jsn)
            if value.persist_mode is PersistMode.CONTROLLED:
                return ControlledValue(dkey, [value])
            elif value.persist_mode is PersistMode.SECURED:
                return value
            else:
                raise ValueError("Unknown persist mode")

    @staticmethod
    def create_from_string(dkey, string):
        try:
            return ValueFactory.create_from_json(dkey, json.loads(string))
        except Exception as ex:
            log.exception(ex)

    @staticmethod
    def create_from_value(value: Value):
        if value.persist_mode is PersistMode.SECURED:
            return value
        elif value.persist_mode is PersistMode.CONTROLLED:
            return ControlledValue(value.key, [value])
        else:
            raise ValueError("Unknown persist mode")


class NodeMessage(JsonSerializable):

    def __init__(self, dkey: bytes, data: str, authorization: Authorization):
        self.__dkey = dkey
        self.authorization = authorization
        self.data = data

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, data):
        self._data = data

    @property
    def authorization(self):
        return self._authorization

    @authorization.setter
    def authorization(self, authorization):
        assert type(authorization) is Authorization or \
               authorization is None
        self._authorization = authorization

    def is_valid(self):
        dval = digest(self.__dkey.hex() + self.data + str(self.authorization.pub_key.exp_time))
        pub_key = self.authorization.pub_key.key
        return Crypto.check_signature(dval, self.authorization.sign, pub_key)

    @staticmethod
    def of_params(dkey: bytes, data, exp_time=None, priv_key_path=Config.PRIVATE_KEY_PATH,
                  pub_key_path=Config.PUBLIC_KEY_PATH):
        log.debug(f'Going to sign {data} with key: [{dkey.hex()}]')

        if isinstance(data, Value) or isinstance(data, ControlledValue):
            data = str(data)

        dval = digest(dkey.hex() + str(data) + str(exp_time))
        with open(priv_key_path) as priv_key:
            signature = Crypto.get_signature(dval, priv_key.read()).hex()
        with open(pub_key_path) as pub_key:
            pub_key = pub_key.read()
        log.debug(f'Successfully signed data with key: [{dkey.hex()}]')

        return NodeMessage(dkey, data, Authorization(PublicKey(pub_key, exp_time), signature))


def is_new_value_valid(dkey, stored_value: Value, new_value: Value):
    try:
        validate_authorization(dkey, new_value)
        return stored_value.authorization.pub_key.key == new_value.authorization.pub_key.key
    except Exception as ex:
        log.exception(ex)
        return False


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


def check_value_json(dct: dict):
    auth = dct.get('authorization')
    p_mode = dct.get('persist_mode')
    data = dct.get('data')

    if not all((auth, p_mode, data)):
        raise InvalidValueFormatException(
            'Invalid value format, value MUST contain following keys: authorization, persist_mode, data')

    if p_mode not in (m.value for m in PersistMode):
        raise InvalidValueFormatException('Invalid value format, persist_mode MUST be set to "SECURED" or "CONTROLLED"')


# TODO: move to value responsibilities
def validate_secure_value(dkey, new_value: Value, stored_value: Value):
    if new_value.persist_mode != PersistMode.SECURED:
        raise UnauthorizedOperationException()
    if new_value.persist_mode != stored_value.persist_mode:
        raise UnauthorizedOperationException()
    if not is_new_value_valid(dkey, stored_value, new_value):
        raise UnauthorizedOperationException()


# TODO: move to value responsibilities
def validate_controlled_value(dkey, new_value: Value, stored_value: list):
    if new_value.persist_mode != PersistMode.CONTROLLED:
        raise UnauthorizedOperationException()
    controlled_value = {}
    nv_pub_key = new_value.authorization.pub_key.key
    for val in stored_value:
        controlled_value[val['authorization']['pub_key']['key']] = Value.of_json(dkey, val)
    if nv_pub_key in controlled_value.keys() and not is_new_value_valid(dkey, controlled_value.get(nv_pub_key), new_value):
            raise UnauthorizedOperationException()


def select_most_common_response(dkey, responses):
    from collections import Counter

    unpack_inner_object = compose(get_field('data'), unpack)
    json_to_value = to_value_with_key(dkey)

    if responses:
        if not isinstance(responses, list):
            responses = [responses]

        values = [unpack_inner_object(r) for r in responses]
        most_common_type = Counter(map(lambda it: type(it), values)).most_common(1)[0][0]
        values = list(filtering_by(most_common_type)(values))

        if most_common_type is list:

            pub_key_value = list(map(lambda x: (x.authorization.pub_key.key, x), map(json_to_value, chain(*values))))
            grouped = defaultdict(list)
            for el in pub_key_value:
                grouped[el[0]].append(el[1])

            result = ControlledValue(dkey, [Counter(key_values).most_common(1)[0][0] for key_values in grouped.values()])

        else:
            result = Counter(map(json_to_value, values)).most_common(1)[0][0]

        return result
    else:
        return None


def to_value_with_key(key):
    return partial(Value.of_json, key)


def check_pkey_type(hex_pub_key):
    assert type(hex_pub_key) is str
