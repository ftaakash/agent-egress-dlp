# Security policy

egressguard is a guidance-level tool: it reduces accidental leaks from cooperative clients and is not a
security boundary (see "What it does not do" in the README).

Please report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on this repository.
Do not open a public issue for a vulnerability.

Of particular interest:

- a way to make egressguard write a matched value in clear to its log or to the agent's output;
- a request that is forwarded although a `block` rule matched it, or that skips inspection on a non-passthrough host;
- decryption of traffic to a passthrough host;
- anything that changes system state (proxy settings, trust stores) or leaves the proxy CA trusted outside a session.

Supported version: the latest release.
