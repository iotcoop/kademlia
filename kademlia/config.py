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
