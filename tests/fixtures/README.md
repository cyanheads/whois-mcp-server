# RDAP fixtures

Captured on 2026-09-30 from public registry services:

| File | Source | HTTP status |
| --- | --- | --- |
| `iana-ipv4.json` | https://data.iana.org/rdap/ipv4.json | 200 |
| `iana-ipv6.json` | https://data.iana.org/rdap/ipv6.json | 200 |
| `arin-test-net.json` | https://rdap.arin.net/registry/ip/192.0.2.1 | 200 |
| `apnic-not-found.json` | https://rdap.apnic.net/ip/2001:db8::1 | 404 |

These preserve the captured response bodies, including registry notices. Tests replay them without contacting the services. TEST-NET demonstrates that special-use address space can have useful RDAP records; documentation IPv6 and unallocated bootstrap space exercise distinct not-found and no-route outcomes.
