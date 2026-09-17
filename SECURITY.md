# Security Policy

## Status

Amnesic Pi is experimental pre-1.0 security software. Do not rely on it as your sole protection where disclosure could cause serious harm.

## Reporting

Please open a minimal private security report through GitHub Security Advisories when available. Avoid posting live bypass details in a public issue before a fix exists.

## Release gate

A release must not be described as fail-closed unless the release candidate has passed:

- policy unit tests;
- nftables syntax validation on target OS;
- Tor-stop network-denial test;
- DNS leak test from a downstream client;
- IPv6 leak test;
- reboot amnesia test.
