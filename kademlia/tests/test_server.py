import json
import unittest

from kademlia.domain.domain import PersistMode
from kademlia.tests.utils import get_signed_value_with_keys
from kademlia.utils import digest
from unittest.mock import Mock
import asyncio

from kademlia.network import Server
from kademlia.protocol import KademliaProtocol


class SwappableProtocolTests(unittest.TestCase):

    def test_default_protocol(self):
        """
        An ordinary Server object will initially not have a protocol, but will
        have a KademliaProtocol object as its protocol after its listen()
        method is called.
        """
        server = Server()
        self.assertIsNone(server.protocol)
        server.listen(8421)
        self.assertIsInstance(server.protocol, KademliaProtocol)
        server.stop()

    def test_custom_protocol(self):
        """
        A subclass of Server which overrides the protocol_class attribute will
        have an instance of that class as its protocol after its listen()
        method is called.
        """

        # Make a custom Protocol and Server to go with hit.
        class CoconutProtocol(KademliaProtocol):
            pass

        class HuskServer(Server):
            protocol_class = CoconutProtocol

        # An ordinary server does NOT have a CoconutProtocol as its protocol...
        server = Server()
        server.listen(8421)
        self.assertNotIsInstance(server.protocol, CoconutProtocol)
        server.stop()

        # ...but our custom server does.
        husk_server = HuskServer()
        husk_server.listen(8421)
        self.assertIsInstance(husk_server.protocol, CoconutProtocol)
        husk_server.stop()


class ServerTests(unittest.TestCase):

    def test_setSecure_putNewValue_Ok(self):
        """
        set_auth should validate value, check authorization and save value to the network
        """
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)

        async def run_test():
            server = Server()

            def async_return(result):
                f = asyncio.Future()
                f.set_result(result)
                return f

            get_signed_value = get_signed_value_with_keys(priv_key_path='kademlia/tests/resources/key.der',
                                                          pub_key_path='kademlia/tests/resources/public.der')
            key_test = 'test key'
            dkey_test = digest(key_test)
            data = json.dumps(get_signed_value(dkey_test, 'data', PersistMode.SECURED).to_json())
            value = get_signed_value(dkey_test, data, PersistMode.SECURED)
            server.get = Mock(return_value=async_return(get_signed_value(dkey_test, data, PersistMode.SECURED).to_json()))
            server.set_digest = Mock(return_value=async_return(True))

            await server.set('test key', value)

            server.get.assert_called_with('test key')

            server.stop()

        coro = asyncio.coroutine(run_test)
        event_loop.run_until_complete(coro())
