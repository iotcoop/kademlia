# Python Distributed Hash Table  &emsp; ![Build Status]

[Build Status]: http://18.224.44.167:8080/buildStatus/icon?job=DHT

**Documentation can be found at [kademlia.readthedocs.org](http://kademlia.readthedocs.org/).**

This library is an asynchronous Python implementation of the [Kademlia distributed hash table](http://en.wikipedia.org/wiki/Kademlia).  It uses the [asyncio library](https://docs.python.org/3/library/asyncio.html) in Python 3 to provide asynchronous communication.  The nodes communicate using [RPC over UDP](https://github.com/bmuller/rpcudp) to communiate, meaning that it is capable of working behind a [NAT](http://en.wikipedia.org/wiki/NAT).

This library aims to be as close to a reference implementation of the [Kademlia paper](http://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf) as possible.

## Installation

```
pip install kademlia
```

## Usage
*This assumes you have a working familiarity with [asyncio](https://docs.python.org/3/library/asyncio.html).*

Assuming you want to connect to an existing network:

```python
import asyncio
from kademlia.network import Server

# Create a node and start listening on port 5678
node = Server()
node.listen(5678)

# Bootstrap the node by connecting to other known nodes, in this case
# replace 123.123.123.123 with the IP of another node and optionally
# give as many ip/port combos as you can for other nodes.
loop = asyncio.get_event_loop()
loop.run_until_complete(node.bootstrap([("123.123.123.123", 5678)]))

# set a value for the key "my-key" on the network
loop.run_until_complete(node.set("my-key", "my awesome value"))

# get the value associated with "my-key" from the network
result = loop.run_until_complete(node.get("my-key"))
print(result)
```

## Initializing a Network
If you're starting a new network from scratch, just omit the `node.bootstrap` call in the example above.  Then, bootstrap other nodes by connecting to the first node you started.

See the examples folder for a first node example that other nodes can bootstrap connect to and some code that gets and sets a key/value.

## Logging
This library uses the standard [Python logging library](https://docs.python.org/3/library/logging.html).  To see debut output printed to STDOUT, for instance, use:

```python
import logging

log = logging.getLogger('kademlia')
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())
```

## Running Tests
To run tests:

```
pip install -r dev-requirements.txt
python -m unittest
```

## Fidelity to Original Paper
The current implementation should be an accurate implementation of all aspects of the paper save one - in Section 2.3 there is the requirement that the original publisher of a key/value republish it every 24 hours.  This library does not do this (though you can easily do this manually).

## API
### **Post data**

* **URL**

    http://`{hostname}`:`{port}`/dht/`:key`

* **Method**

    `POST`

* **URL Params**

    **Required**:

        key=[String]

* **Success Response:**

  * **Code:** 200 Ok

* **Error Response:**

    * **Code:** 401 UNAUTHORIZED

    OR

    * **Code:** 400 BAD REQUEST

* **Body Structure:**

```
{
    "data": "string_payload",
    "persist_mode": "SECURED",
    "authorization": {
        "pub_key": {
            "key": "0224d2079e86e937224f08aa37a857ca6116546868edde549d0bd6b8536af9d554",
            "exp_time": null
        },
        "sign": "d3f1d0cfeb6e9913ffe1759e9a5a331a65dade83f53ca6ef60f2c588238c4cc2497d6f48b1968e31e98fc749d1887d6bb546718f2676a3308f9701a6b399c2c1"
    }
}
```

* **Sample Call:**

```
curl --header "Content-Type: application/json" --request POST --data '{
    "data": "string_payload",
    "persist_mode": "SECURED",
    "authorization": {
        "pub_key": {
            "key": "0224d2079e86e937224f08aa37a857ca6116546868edde549d0bd6b8536af9d554",
            "exp_time": null
        },
        "sign": "d3f1d0cfeb6e9913ffe1759e9a5a331a65dade83f53ca6ef60f2c588238c4cc2497d6f48b1968e31e98fc749d1887d6bb546718f2676a3308f9701a6b399c2c1"
    }
}' http://localhost:8080/dht/test_id

```

### **Get data**

* **URL**

    http://`{hostname}`:`{port}`/dht/`:key`

* **Method**

    `GET`

* **URL Params**

    **Required**:

        key=[String]

* **Success Response:**

  * **Code:** 200 Ok </br>
    **Content:** 
    
    ```{
      "authorization": {
        "sign":     "9fac8ed0831013755af002db97c09ad0c5f2ecce2a3b4e6622844d6bc892f9673b6ed4113b15d7d27206cd8c52eac69b6811fe52e776024d96fb63d6a02fc2d6",
        "pub_key": {
          "key":    "02ff6438e6ffb6d630c8ca6adac13cee4e3b5542ad56aa90a91caaaccc673008f3",
          "exp_time": null
        }
      },
      "persist_mode": "SECURED",
      "data": "{\"authorization\": {\"sign\":   \"d3f1d0cfeb6e9913ffe1759e9a5a331a65dade83f53ca6ef60f2c588238c4cc2497d6   f48b1968e31e98fc749d1887d6bb546718f2676a3308f9701a6b399c2c1\",     \"pub_key\": {\"key\":  \"0224d2079e86e937224f08aa37a857ca6116546868edde549d0bd6b8536af9d554\",   \"exp_time\": null}}, \"data\": \"string_payload\", \"persist_mode\":    \"SECURED\"}"
        }
    ```

* **Sample Call:**

```
curl http://localhost:8080/dht/test_id
```
