import os


class Config:

    # DHT main properties configs
    K_SIZE = os.getenv('K_SIZE', 20)
    ALPHA = os.getenv('ALPHA', 3)
    VALUES_TO_WAIT = os.getenv('VALUES_TO_WAIT', 1)

    PRIVATE_KEY_PATH = os.getenv('PRIVATE_KEY_PATH', 'key.pem')
    PUBLIC_KEY_PATH = os.getenv('PUBLIC_KEY_PATH', 'public.pem')
