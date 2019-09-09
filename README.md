# Netbox DNS update webhook

A simple Netbox webhook to perform DNS updates based on the `dns_name`
attribute of `ipam.ipaddress` objects, updating both forward (A/AAAA)
and reverse (PTR).

It has an updater class for RFC2136 dynamic DNS updates, but could be
extended to access other APIs or databases.  The backend just needs to be
able to add and remove specific A/AAAA and PTR records, and list existing
ones.

It is assumed that Netbox maintains only the "primary" name for each IP
address - that is, the one which the PTR record refers to.  Additional
records such as MX or CNAME, or additional A/AAAA records pointing to the
same IP address, still need to be added outside of Netbox.

## Dependencies

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

## Caveats and limitations

The Netbox webhook update message does not [provide the old
data](https://github.com/netbox-community/netbox/issues/3451).  This makes
this updater much more complicated that it otherwise might be.

The webhook performs DNS queries to find out what records already exist, to
work out whether records needed to be added or removed.

* Any save of an ipaddress object will cause the DNS records to be queried
  and reconciled, even if the `address` and `dns_name` have not changed
* **If you save any ipaddress object where the dns_name is empty, this will
  cause all existing PTR records for that IP address to be removed**
* If you change *both* the `address` and `dns_name` of an ipaddress object
  at the same time, the old name and address will remain in the DNS
* You have to configure each zone that you want to update.  It does not work
  out for itself where the zone cuts are.
* Netbox does not have a [unique constraint](https://github.com/netbox-community/netbox/issues/3490)
  on `(dns_name, family)`.  Bad things could happen if two different addresses
  have the same DNS name, except when one is IPv4 and one is IPv6.
* No SSL support
* See also [this bug](https://github.com/netbox-community/netbox/issues/3489)
  which causes an exception when you delete an ipaddress.

## Licence

This work is licensed under the same terms as Netbox itself, which is Apache
2.0.

It Works For Me™, but you should be prepared to hack python code if it
doesn't work for you.