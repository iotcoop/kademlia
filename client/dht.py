import logging
import asyncio
import sys

from aiohttp import web

from kademlia.domain.domain import Value
from kademlia.exceptions import InvalidSignException, UnauthorizedOperationException, InvalidValueFormatException
from kademlia.network import Server
from kademlia.storage import DiskStorage
from kademlia.utils import digest


async def read_key(request):
    global server
    key = request.match_info.get('key')
    try:
        resp = await server.get(key)
    except:
        raise web.HTTPInternalServerError()

    return web.json_response(resp.to_json())


async def set_value(request):
    global server

    key = request.match_info.get('key')
    try:
        data = await request.json()
        await server.set(key, Value.of_json(digest(key), data))
    except InvalidSignException:
        raise web.HTTPBadRequest
    except UnauthorizedOperationException:
        raise web.HTTPUnauthorized
    except InvalidValueFormatException:
        raise web.HTTPBadRequest

    return web.HTTPOk()


if __name__ == '__main__':
    KADEMLIA_PORT = int(sys.argv[3])
    CONNECT_PORT = int(sys.argv[2])
    API_PORT = int(sys.argv[4])
    KEY_ABSENT_MESSAGE = 'No such key'
    NO_KEYS = 'No keys'

    loop = asyncio.get_event_loop()
    server = Server(storage=DiskStorage())
    server.listen(KADEMLIA_PORT)

    loop.set_debug(True)

    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    log = logging.getLogger('kademlia')
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)

    if sys.argv[1] != "127.0.0.1":
        bootstrap_node = (sys.argv[1], CONNECT_PORT)
        loop.run_until_complete(server.bootstrap([bootstrap_node]))

    app = web.Application()
    app.add_routes([web.get('/dht/{key}', read_key)])
    app.add_routes([web.post('/dht/{key}', set_value)])

    web.run_app(app, port=API_PORT)
