# Networking

## Default interface model

`/etc/amnesic-pi/network.env` defines two roles:

- `UPLINK_IF`: interface with Internet reachability
- `CLIENT_IF`: interface receiving downstream client traffic

The service refuses malformed names and refuses to use the same interface for both roles.

## Why no FORWARD accept rule exists

This is a transparent proxy appliance, not a normal IP router. Downstream TCP and DNS traffic is redirected into local Tor listeners in nftables `prerouting`; all remaining forwarding is denied.

## UDP

Tor does not provide a generic UDP transport. Stage 1 therefore drops downstream UDP except DNS to Tor's DNSPort. QUIC/HTTP3 will fail; well-behaved browsers normally fall back to TCP.

## DNS

Downstream UDP DNS is redirected to the local Tor DNSPort. Stage 1 does not support arbitrary DNS record types or TCP DNS through Tor DNSPort.

## IPv6

Disabled in Stage 1. A future IPv6 implementation must add equivalent transparent-proxy semantics and leak tests before it is enabled.

## Local management

The default firewall does **not** open SSH or a web UI on the client interface. Use a local console during early development. A management plane, if added, should have a separate explicit trust boundary.
