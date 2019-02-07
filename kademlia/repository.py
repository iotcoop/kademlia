import json
import logging
import requests

from kademlia.utils import digest512

log = logging.getLogger(__name__)


class ValidatorRepository:

    def __init__(self, data_reader):
        self._read = data_reader

    def get_by_id(self, record_id):
        return self._read(record_id)


def from_dtl(url):
    def reading(namespace):
        prefix = digest512(namespace).hex()[:6]

        def read(resource_id):
            resource_id = prefix + digest512(resource_id).hex()[:64]
            return get_json(compose_url(url, resource_id))
        return read
    return reading


def get_json(url):
    try:
        log.debug(f"Executing GET request on url: {url}")
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, json.decoder.JSONDecodeError):
        return None


def compose_url(*url_parts):
    return "/".join(url_parts)
