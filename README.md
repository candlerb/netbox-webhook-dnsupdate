# Netbox DNS update webhook

A simple Netbox webhook to perform DNS updates based on the `dns_name`
attribute of `ipam.ipaddress` objects, updating both forward (A/AAAA)
and reverse (PTR).

It has an updater class for RFC2136 dynamic DNS updates, but could be
extended to access other APIs or databases.  The backend just needs to be
able to add and remove specific A/AAAA and PTR records.

It is assumed that Netbox maintains only the "primary" name for each IP
address - that is, the one which the PTR record refers to.  Additional
records such as MX or CNAME, or additional A/AAAA records pointing to the
same IP address, still need to be added outside of Netbox.

## Dependencies

**This version requires netbox v2.11+ as it uses the prechange/postchange
feature in webhooks.  An older version is in the `pre-v2.11` branch**

Requires [dnspython](http://www.dnspython.org/examples.html).  Tested with
version 0.16, which can be installed using pip:

```
pip3 install dnspython
```

Alternatively, you can install from your package manager, but you may get an
older version.

```
apt-get install python3-dnspython
```

## Installation

Edit `nb_dns_run.py` to configure the zones to be updated, and to set an
optional API key for Netbox to authenticate to the webhook.

Run `python3 nb_dns_run.py`

Webhook will listen on port 7001 by default.

To prevent any DNS updates taking place, but instead log what DNS updates it
would have done, uncomment this line:

```
#ddns = DummyUpdater()
```

## Logic

When an IP address is updated and the address or DNS name is different to
what it was before:

* If an old name was present, then the A (or AAAA) and PTR records are removed
* If a new name is present, then new A (or AAAA) and PTR records are created

## Caveats and limitations

* You have to configure each zone that you want to update.  It does not work
  out for itself where the zone cuts are.
* Netbox does not have a [unique constraint](https://github.com/netbox-community/netbox/issues/3490)
  on `(dns_name, family)`.  Bad things could happen if two different addresses
  have the same DNS name, except when one is IPv4 and one is IPv6.  Bad
  things can happen if the same IP address exists multiple times, e.g. in
  different VRFs.
* No SSL support

## Licence

This work is licensed under the same terms as Netbox itself, which is Apache
2.0.

It Works For Me™, but you should be prepared to hack python code if it
doesn't work for you.
