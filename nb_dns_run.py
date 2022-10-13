#!/usr/bin/env python3

# This is the configuration and startup for the webhook server.
# Edit to suit.

import dns.tsig, dns.tsigkeyring
from nb_dns_updater import DummyUpdater, DDNSUpdater, simple_server

SERVER = '127.0.0.1'
KEY_ID = 'my-key-name'
SECRET = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX='
KEYRING = dns.tsigkeyring.from_text({
    KEY_ID: SECRET,
})
KEYALGORITHM = dns.tsig.HMAC_SHA256
WEBHOOK_SECRET = 'VERY RANDOM STRING'

ddns = DDNSUpdater(server=SERVER, keyring=KEYRING, keyalgorithm=KEYALGORITHM)
#ddns = DummyUpdater()

# List all the zones you wish to update, pointing at the relevant
# updater object.  You can have different zones on different
# servers and/or with different keys
ZONES = {
    "example.com": ddns,
    "168.192.in-addr.arpa": ddns,
    "8.b.d.0.1.0.0.2.ip6.arpa": ddns,
}

if __name__ == "__main__":
    simple_server(ZONES, api_key=WEBHOOK_SECRET)
