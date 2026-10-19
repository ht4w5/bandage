# 08: Fetch hardening: HTTPS with mutual TLS

**What to build:** a routing-box deployment fetches reports over the network
securely: HTTPS with server verification and optional mutual TLS, reusing
bandaid's certificate surface so the operator's existing PKI runbook applies
unchanged. Plain HTTP keeps working for the localhost case. There is no
insecure mode.

**Blocked by:** 01 — Walking skeleton

**Status:** ready-for-agent

- [ ] The report endpoint accepts HTTP and HTTPS URLs
- [ ] `--cacert` verifies the server against a given CA; `--cert`/`--key` present a client certificate (mTLS); all mirror bandaid's flag surface
- [ ] A client certificate without its key (or vice versa) is rejected at startup validation
- [ ] The fetch timeout is configurable with bandaid's default
- [ ] No insecure-skip-verify mode exists
- [ ] Seam tests drive an HTTPS test server requiring client certificates: mutual-TLS success, wrong-CA failure (cycle refuses, last rules kept), and the plain-HTTP case

Context: spec `../spec.md` (Transport); bandaid's fetch surface in the
reference checkout. The TLS-termination deployment note lands in ticket 09.
