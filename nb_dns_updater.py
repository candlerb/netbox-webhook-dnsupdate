"""
This is a dynamic DNS webhook for Netbox.  It updates A/AAAA and PTR records
based on the dns_name attribute of ipam.ipaddress records.
"""

import dns.name
import dns.update
import dns.query
import dns.rcode
import dns.reversename
import hashlib
import hmac
import json
import socket
import sys

IP6_ARPA = dns.name.from_text("ip6.arpa")

class DummyUpdater:
    """
    Just print the updates which would be done, without doing anything
    """
    def __init__(self, debug=lambda x: print(x, file=sys.stderr)):
        self.debug = debug

    def __call__(self, zone, updates):
        if self.debug:
            self.debug("Zone %s" % zone)
            for u in updates:
                self.debug(u)

class DDNSUpdater:
    def __init__(self, server, debug=lambda x: print(x, file=sys.stderr), **kwargs):
        # we can accept either an IP address or a hostname
        self.server = socket.getaddrinfo(server, None)[0][4][0]
        self.debug = debug
        self.kwargs = kwargs

    def __call__(self, zone, updates):
        """
        Takes a list of updates and sends a DDNS update request
        """
        if self.debug:
            self.debug("Zone %s" % zone)
            for u in updates:
                self.debug(u)

        updater = dns.update.Update(zone, keyalgorithm=dns.tsig.HMAC_MD5, **self.kwargs)
        for (action, args) in updates:
            getattr(updater, action)(*args)
        response = dns.query.tcp(updater, self.server)
        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            print("DNS update for %s failed: %s" % (zone, dns.rcode.to_text(rcode)),
                  file=sys.stderr)

class UpdateMapper:
    """
    This class maintains a mapping of zones to updaters.  When we want to update
    a particular record, it identifies the correct zone and appends to a list of
    updates.  At commit time, the list of updates is passed to the relevant updater.
    """
    def __init__(self, zones):
        self.zones = { dns.name.from_text(n): v for n, v in zones.items() }

    def begin(self):
        """Return a mapping of dns.name to updates"""
        return {}

    def _find(self, dnsname):
        """Map a name to its enclosing zone"""
        while True:
            if dnsname in self.zones:
                return dnsname
            try:
                dnsname = dnsname.parent()
            except dns.name.NoParent:
                return None

    def _record(self, ctx, action, dnsname, *args):
        """
        Record an update required.  Format is same as calls to dns.update.Update but
        using full names instead of relative names, e.g.

        self._record(ctx, "replace", dns.name.from_text("foo.example.com"), 300, "a", "192.0.2.1")
        """
        zonename = self._find(dnsname)
        if zonename is None:
            return
        if zonename not in ctx:
            ctx[zonename] = []
        ctx[zonename].append((action, (dnsname.relativize(zonename).to_text(), *args)))

    def add(self, ctx, dnsname, ttl, rrtype, data):
        self._record(ctx, "add", dnsname, ttl, rrtype, data)

    def replace(self, ctx, dnsname, ttl, rrtype, data):
        self._record(ctx, "replace", dnsname, ttl, rrtype, data)

    def delete(self, ctx, dnsname, rrtype, data=None):
        self._record(ctx, "delete", dnsname, rrtype, data)

    def commit(self, ctx):
        for n, updates in ctx.items():
            self.zones[n](n, updates)

class DNSWebHook:
    """
    WSGI application to receive webhook requests for ipaddress objects
    and apply dynamic DNS updates.  Since the webhook doesn't include
    the previous value of address or name, it makes DNS queries to find
    stale records to delete.
    """
    def __init__(self, mapper, api_key=None, ttl=3600):
        self.mapper = mapper
        self.api_key = api_key.encode('utf8') if isinstance(api_key, str) else api_key
        self.ttl = ttl

    def __call__(self, environ, start_response):
        headers = [('Content-type', 'text/plain')]
        if environ['REQUEST_METHOD'] != 'POST':
            status = '405 Method not allowed'
            start_response(status, headers)
            return [b'Method not allowed']

        try:
            request_body_size = int(environ.get('CONTENT_LENGTH', 0))
        except (ValueError):
            request_body_size = 0
        request_body = environ['wsgi.input'].read(request_body_size)

        if self.api_key:
            hmac_prep = hmac.new(
                key=self.api_key,
                msg=request_body,
                digestmod=hashlib.sha512
            )
            if environ.get('HTTP_X_HOOK_SIGNATURE') != hmac_prep.hexdigest():
                status = '403 Forbidden'
                start_response(status, headers)
                return [b'X-Hook-Signature missing or invalid']

        body = json.loads(request_body.decode('UTF-8'))
        if body["model"] != "ipaddress":
            status = '400 Wrong model'
            start_response(status, headers)
            return [b'Wrong model']
        snapshots = body["snapshots"]
        oldaddress = newaddress = oldname = newname = None
        pre = snapshots["prechange"]
        if pre:
            oldaddress = pre["address"].split("/")[0]
            oldname = pre["dns_name"]
        post = snapshots["postchange"]
        if post:
            newaddress = post["address"].split("/")[0]
            newname = post["dns_name"]

        self.update_dns(oldaddress, oldname, newaddress, newname)

        status = '200 OK'  # HTTP Status
        start_response(status, headers)
        return [b'OK']

    def update_dns(self, oldaddress, oldname, newaddress, newname):
        """
        Core update logic:

        - Remove existing A/AAAA record from oldname
          to oldaddress, and PTR record from oldaddress to oldname

        - Add A/AAAA record from newname to newaddress,
          and PTR record from newaddress to newname
        """
        # Short cut: no changes
        if not oldname and not newname:
            return  # no DNS both before and after
        if oldname == newname and oldaddress == newaddress:
            return  # same DNS both before and after

        ctx = self.mapper.begin()

        if oldaddress and oldname:
            revname = dns.reversename.from_address(oldaddress)
            rrtype = "AAAA" if revname.is_subdomain(IP6_ARPA) else "A"
            rrname = dns.name.from_text(oldname)
            self.mapper.delete(ctx, rrname, rrtype, oldaddress)
            self.mapper.delete(ctx, revname, "PTR", rrname.to_text())

        if newaddress and newname:
            revname = dns.reversename.from_address(newaddress)
            rrtype = "AAAA" if revname.is_subdomain(IP6_ARPA) else "A"
            rrname = dns.name.from_text(newname)
            self.mapper.add(ctx, rrname, self.ttl, rrtype, newaddress)
            self.mapper.add(ctx, revname, self.ttl, "PTR", rrname.to_text())

        self.mapper.commit(ctx)

def simple_server(zones, host='', port=7001, **kwargs):
    from wsgiref.simple_server import make_server
    # TODO: SSL
    # Note: does not support IPv6. See
    # https://github.com/bottlepy/bottle/issues/525
    mapper = UpdateMapper(zones)
    app = DNSWebHook(mapper, **kwargs)
    httpd = make_server(host, port, app)
    httpd.serve_forever()

if __name__ == "__main__":
    # Quick hack for testing from CLI: pass old address, old name,
    # new address and new name, and it shows the updates it would make
    mapper = UpdateMapper({"." : DummyUpdater()})
    hook = DNSWebHook(mapper)
    hook.update_dns(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
