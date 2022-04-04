#!/usr/bin/env python3

# This is the configuration and startup for the webhook server.
# Edit to suit.

import dns.tsig, dns.tsigkeyring
from dotenv import load_dotenv, find_dotenv
from os.path import join, dirname
import os, json
from nb_dns_updater import DummyUpdater, DDNSUpdater, simple_server

load_dotenv(find_dotenv())

key_id = os.getenv("KEY_ID")
secret = os.getenv("SECRET")
server = os.getenv("SERVER")
keyalgorithm = os.getenv("KEYALGORITHM")
webhook_secret = os.getenv("WEBHOOK_SECRET")
zones = json.loads(os.getenv("ZONES"))

KEYRING = dns.tsigkeyring.from_text({
    key_id: secret,
})

ddns = DDNSUpdater(server=server, keyring=KEYRING, keyalgorithm=keyalgorithm)
#ddns = DummyUpdater()

# List all the zones you wish to update, pointing at the relevant
# updater object.  You can have different zones on different
# servers and/or with different keys
ZONES = { z: ddns for z in zones }

if __name__ == "__main__":
    simple_server(ZONES, api_key=webhook_secret)
