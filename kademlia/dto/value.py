from kademlia.crypto import PublicKey
from kademlia.helpers import JsonSerializable


class Value(JsonSerializable):

    def __init__(self, data, authorization=None):
        self.data = data
        self.authorization = authorization

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

    @classmethod
    def of_auth(cls, data, auth):
        assert type(auth) is Authorization
        return cls(data, auth)

    @classmethod
    def of_data(cls, data):
        return cls(data)

    @staticmethod
    def of_json(dct):
        assert 'authorization' in dct
        assert 'data' in dct

        if dct['authorization'] is None:
            return Value.of_data(dct['data'])
        else:
            return Value.of_auth(dct['data'], Authorization.of_json(dct['authorization']))


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


def check_dht_value_type(value):
    """
    Checks to see if the type of the value is a valid type for
    placing in the dht.
    """
    typeset = {int, float, bool, str, bytes}
    return type(value) in typeset
