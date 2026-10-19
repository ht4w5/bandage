# 08: Fetch hardening: HTTPS with mutual TLS

**What to build:** a routing-box deployment fetches reports over the network
securely: HTTPS with server verification and optional mutual TLS, reusing
bandaid's certificate surface so the operator's existing PKI runbook applies
unchanged. Plain HTTP keeps working for the localhost case. There is no
insecure mode.

**Blocked by:** 01 — Walking skeleton

**Status:** resolved

- [x] The report endpoint accepts HTTP and HTTPS URLs
- [x] `--cacert` verifies the server against a given CA; `--cert`/`--key` present a client certificate (mTLS); all mirror bandaid's flag surface
- [x] A client certificate without its key (or vice versa) is rejected at startup validation
- [x] The fetch timeout is configurable with bandaid's default
- [x] No insecure-skip-verify mode exists
- [x] Seam tests drive an HTTPS test server requiring client certificates: mutual-TLS success, wrong-CA failure (cycle refuses, last rules kept), and the plain-HTTP case

Implemented on integration branch `feat/splint-nft` (merge commit `60bea99`; cross-ticket code-review fixes through `1879da4`). The TLS-termination deployment note landed in `09-deployment-and-docs.md`.

Context: spec `../spec.md` (Transport); bandaid's fetch surface in the
reference checkout. The TLS-termination deployment note lands in ticket 09.
