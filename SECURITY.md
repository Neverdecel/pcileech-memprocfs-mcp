# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Report privately via [GitHub Security Advisories](https://github.com/Neverdecel/pcileech-memprocfs-mcp/security/advisories/new)
(the "Report a vulnerability" button under the **Security** tab). You'll get an
acknowledgement and a fix or mitigation will be coordinated before any public
disclosure.

When reporting, please include:

- A description of the issue and its impact
- Steps to reproduce (a minimal proof of concept is ideal)
- Affected version / commit

## Supported versions

This project tracks the latest release. Fixes land on `main` and ship in the
next tagged release. Older tags are not patched.

## Responsible use

This tool drives **DMA-based memory access** against a target system via
PCILeech / MemProcFS. It can read and write arbitrary physical and virtual
memory on a connected machine.

It is intended **only** for:

- Authorized security research and penetration testing
- Debugging and forensics on systems you own or are authorized to access
- Educational and CTF use

Using it to access systems you do not own or have explicit written permission
to test may be illegal. **You** are solely responsible for complying with all
applicable laws and for any consequences of use. See the
[Disclaimer](README.md#disclaimer) in the README.
