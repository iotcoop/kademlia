#!/bin/bash

DEFAULT_KADEMLIA_PORT=8468
DEFAULT_API_PORT=8080

if [ -z "$CONNECT_IP" ]; then
  CONNECT_IP="127.0.0.1"
fi

if [ -z "$CONNECT_PORT" ]; then
  CONNECT_PORT=$DEFAULT_KADEMLIA_PORT
fi

if [ -z "$KADEMLIA_PORT" ]; then
  KADEMLIA_PORT=$DEFAULT_KADEMLIA_PORT
fi

if [ -z "$API_PORT" ]; then
  API_PORT=$DEFAULT_API_PORT
fi

if [ "$DEV" = true ] ; then
    apk add curl
fi

python3 -m secp256k1 privkey -p  > keys
sed -n '2 p' keys | cut -d ' ' -f 3 | tr -d '\n' > public.der
sed -n '1 p' keys | tr -d '\n' > key.der
rm keys

exec python /app/dht.py $CONNECT_IP $CONNECT_PORT $KADEMLIA_PORT $API_PORT