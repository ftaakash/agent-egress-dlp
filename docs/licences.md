# Dependency licences

Reviewed on 2026-11-27 for egressguard 0.3.0 (mitmproxy 12.3.1, mitmproxy_rs 0.12.16).

**Method.** A clean virtual environment on Windows 11 / Python 3.14 with only `pip install .` (no dev extras):
42 packages besides pip and egressguard, 83 MB of site-packages. For each one: the `License-Expression` and
`License` metadata, the licence classifiers and the licence files shipped in the wheel. Where the metadata
was empty, the upstream repository at the released tag. Packages installed only on other platforms or
Python versions were checked on PyPI and upstream.

## Summary

- egressguard itself is MIT and contains no third-party code. It depends on the packages below; pip installs
  them separately, each under its own licence.
- Everything is permissive (MIT, BSD, Apache-2.0, PSF, MIT-0) except:
  - **weak copyleft (LGPL):** `ldap3` (LGPL v3), `urwid` (LGPL-2.1-only), and on Windows only
    `mitmproxy-windows` (LGPL-3.0-or-later; it bundles the WinDivert driver, LGPL-3.0 or GPL-2.0) and `pydivert`
    (LGPL-3.0-or-later OR GPL-2.0-or-later);
  - **file-level copyleft (MPL-2.0):** `certifi`, and the Public Suffix List inside `publicsuffix2`.
- The open question from v0.1 is closed: `mitmproxy_rs` and `mitmproxy-linux` ship wheels with no licence
  metadata, but both are MIT upstream (`LICENSE` and `Cargo.toml` at tag v0.12.16, including the Linux eBPF part).
- None of these is GPL-only. The GPL option of `pydivert` and WinDivert is one of two choices; the LGPL one applies.

## What this means (not legal advice)

- Using egressguard, or distributing it as source or as a wheel that depends on these packages from PyPI, is
  compatible with MIT: the LGPL and MPL packages are used unmodified as separate, replaceable libraries.
- If egressguard is ever shipped as one bundled executable (PyInstaller or similar), the bundle must include the
  LGPL and MPL licence texts and keep the LGPL libraries replaceable, and modified MPL files would need their
  source published. That is not done today.
- The LGPL packages are installed because mitmproxy requires them, for features egressguard does not use: LDAP
  proxy authentication (`ldap3`), the console UI (`urwid`), and transparent or local capture on Windows
  (`pydivert`, `mitmproxy-windows`). Checked on Windows: when the proxy starts, mitmproxy's default add-ons
  still import `ldap3`, `pydivert` and `mitmproxy_windows` (`urwid` is not imported), so they are loaded as
  unmodified libraries even though their features are never switched on.

## Full list

| Package | Version | Licence | Note |
|---|---|---|---|
| aioquic | 1.2.0 | BSD-3-Clause |  |
| argon2-cffi | 25.1.0 | MIT |  |
| argon2-cffi-bindings | 26.2.0 | MIT |  |
| asgiref | 3.12.1 | BSD-3-Clause |  |
| attrs | 26.1.0 | MIT |  |
| bcrypt | 5.0.0 | Apache-2.0 |  |
| blinker | 1.9.0 | MIT |  |
| brotli | 1.2.1 | MIT |  |
| certifi | 2026.11.20 | MPL-2.0 | file-level copyleft |
| cffi | 2.1.1 | MIT-0 |  |
| click | 8.5.1 | BSD-3-Clause |  |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |  |
| Flask | 3.1.3 | BSD-3-Clause |  |
| h11 | 0.16.0 | MIT |  |
| h2 | 4.4.1 | MIT |  |
| hpack | 4.2.0 | MIT |  |
| hyperframe | 6.1.0 | MIT |  |
| itsdangerous | 2.2.0 | BSD-3-Clause |  |
| Jinja2 | 3.1.6 | BSD-3-Clause |  |
| kaitaistruct | 0.11 | MIT |  |
| ldap3 | 2.9.1 | LGPL-3.0 (metadata says "LGPL v3"; LICENSE is the LGPL 3 text) | weak copyleft |
| MarkupSafe | 3.0.4 | BSD-3-Clause |  |
| mitmproxy | 12.3.1 | MIT (LICENSE file; the metadata field holds the licence text) |  |
| mitmproxy-windows | 0.12.16 | LGPL-3.0-or-later (bundles WinDivert, LGPL-3.0 or GPL-2.0) | weak copyleft |
| mitmproxy_rs | 0.12.16 | MIT (no licence in the wheel metadata; upstream LICENSE and Cargo.toml at tag v0.12.16) |  |
| publicsuffix2 | 2.20191221 | MIT and MPL-2.0 | file-level copyleft |
| pyasn1 | 0.6.5 | BSD-2-Clause |  |
| pycparser | 3.12 | BSD-3-Clause |  |
| pydivert | 3.1.3 | LGPL-3.0-or-later OR GPL-2.0-or-later | weak copyleft |
| pylsqpack | 0.3.24 | BSD-3-Clause |  |
| pyOpenSSL | 26.4.0 | Apache-2.0 |  |
| pyparsing | 3.3.3 | MIT |  |
| pyperclip | 1.11.0 | BSD-3-Clause |  |
| ruamel.yaml | 0.19.1 | MIT |  |
| service-identity | 26.1.0 | MIT |  |
| sortedcontainers | 2.4.0 | Apache-2.0 |  |
| tornado | 6.5.10 | Apache-2.0 |  |
| typing_extensions | 4.16.0 | PSF-2.0 |  |
| urwid | 4.0.13 | LGPL-2.1-only | weak copyleft |
| wcwidth | 0.9.5 | MIT |  |
| Werkzeug | 3.1.9 | BSD-3-Clause |  |
| wsproto | 1.3.2 | MIT |  |
| mitmproxy-linux (Linux only) | 0.12.16 | MIT (no licence in the wheel metadata; upstream Cargo.toml at tag v0.12.16, eBPF part also MIT) | |
| mitmproxy-macos (macOS only) | 0.12.16 | MIT | |
| backports.zstd (Python < 3.14 only) | 1.7.0 | PSF-2.0 | |
