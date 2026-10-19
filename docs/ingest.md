# Ingest: choosing a transport

bandage receives events over syslog. `configs/bandage.yml` selects the
driver and transport; every syslog message must carry exactly one
access-log line (v0: nginx JSON in the bandage nginx log format, see
`ingest.parser`) — each message becomes one [Event](../GLOSSARY.md) in
the pipeline.

```yaml
ingest:
  driver: syslog               # driver-keyed; more drivers later
  syslog:
    network: unixgram          # tcp | udp | unixgram
    listen: /run/bandage/log.sock
  parser: nginx                # nginx JSON in the bandage nginx log format (flux-compatible)
```

`ingest.syslog.network` accepts `tcp`, `udp` or `unixgram`;
`ingest.syslog.listen` is the listen address (host:port, or a socket
path for unixgram). Unknown keys and invalid values abort startup.

## The bandage nginx log format

`ingest.parser: nginx` parses one JSON access-log line per message: the
bandage nginx log format. Bandage ships it ready to include —
[`configs/nginx/bandage_log.conf`](../configs/nginx/bandage_log.conf)
defines `log_format bandage escape=json` with exactly the parser's seven
mapped fields (`time`, `client`, `method`, `url`, `status`, `sent`,
`agent`), so wiring ingest is `include .../bandage_log.conf;` and
`access_log <path> bandage;` — no field contract to reverse-engineer.

Migration (flux-compatible): lines from an existing flux `log_format`
keep parsing unchanged — its extra `host`/`server`/`duration` fields
(and any others) are accepted and ignored — while the `bandage` format
name never collides with an existing `flux` definition.

## Recommendation: udp or unixgram at high rate

For high-rate deployments run udp (remote senders) or unixgram (senders
on the same host). Both are datagram transports: **one datagram is one
message**. There is no per-sender connection state and no framing work
— the driver reads whole datagrams and forwards each message as it
arrives. unixgram skips the network stack entirely and is the cheapest
option when the log source is local; it is what
`configs/bandage.yml` ships with.

## The tcp cost

`network: tcp` is a byte stream, not messages: every message must be
framed out of the stream. The driver keeps one goroutine and one
scanner per connection and splits it into messages (newline framing,
RFC 6587 octet counting when detected), so:

- each sender costs a connection and a goroutine, and every message
  costs a framing scan where a datagram costs nothing;
- a stream is ordered and reliable: a stalled sender head-of-line
  blocks its own messages behind the ones it has not finished sending,
  and tcp's flow control turns an overloaded receiver into slow
  senders rather than visible loss;
- framing failures are stream-level: a message longer than the
  scanner's 64 KiB limit ends that connection's stream, taking the
  remaining messages with it.

Use tcp when senders are remote and require tcp's delivery behavior
(retries, congestion control) or can only speak tcp — not for
high-rate local feeds.

## The UDP kernel-buffer caveat

On udp, datagrams queue in a finite kernel receive buffer until the
driver reads them (the driver requests 64 KiB; the kernel clamps the
size — `net.core.rmem_max` on Linux). If bandage's reader lags behind a
burst, **the kernel drops datagrams from the queue — silently**:

- dropped datagrams never reach the pipeline, so they appear in
  neither `received` nor `dropped` on `GET /stats` (`dropped` counts
  parse failures only). Kernel loss is invisible in bandage's counters;
- watch the host's UDP counters instead — `nstat -az UdpRcvbufErrors`
  or `netstat -su` (receive buffer errors) — and treat any growth as
  lost events;
- to reduce it: raise `net.core.rmem_max` (and `net.core.rmem_default`)
  so the requested buffer is granted, keep senders burst-shy, and
  prefer unixgram on-host — its socket buffer pushes back on the
  sender (send blocks or fails) instead of discarding messages.

Nothing here is configurable inside bandage beyond the transport keys
above: the buffer and kernel behavior are the operating system's.
