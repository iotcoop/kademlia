import os

from kademlia.utils import load_from_file


class Config:

    # DHT main properties configs
    K_SIZE = os.getenv('K_SIZE', 20)
    ALPHA = os.getenv('ALPHA', 3)
    VALUES_TO_WAIT = os.getenv('VALUES_TO_WAIT', 20)

    PRIVATE_KEY_PATH = os.getenv('PRIVATE_KEY_PATH', 'key.der')
    PUBLIC_KEY_PATH = os.getenv('PUBLIC_KEY_PATH', 'public.der')

    NODE_PRIVATE_KEY = load_from_file(PRIVATE_KEY_PATH)
    NODE_PUBLIC_KEY = load_from_file(PUBLIC_KEY_PATH)

    # Sawtooth properties
    DHT_NAMESPACE = 'eqt_dht.values'
    VALIDATOR_HOST = os.getenv('VALIDATOR_HOST', '127.0.0.1')
    VALIDATOR_PORT = os.getenv('VALIDATOR_PORT', '8008')
    VALIDATOR_URL = f'http://{VALIDATOR_HOST}:{VALIDATOR_PORT}'
