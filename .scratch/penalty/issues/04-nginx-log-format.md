# 04: Shipped nginx log_format for ingest

**What to build:** An operator wires access-log ingest without reverse-engineering the parser: bandage ships an nginx config snippet (operator-facing artifact, contract name `configs/nginx/bandage_log.conf`) containing exactly one directive — `log_format bandage escape=json` with the parser's seven mapped fields: `time` (`$msec`, rendered as a quoted JSON string), `client`, `method`, `url`, `status`, `sent`, and `agent`. `agent` is included although the parser treats it as optional, so agent-based rules (the tripwire pattern) work with the shipped format; the reserved `host`/`server`/`duration` superset is deliberately excluded and remains accepted-and-ignored for deployments that add fields. The file carries no vhost and no usage comments. The ingest docs, the parser's comment and the daemon config comment name it "the bandage nginx log format" with a "(flux-compatible)" migration note.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Shipped snippet contains exactly one directive: `log_format bandage escape=json` with exactly the seven mapped fields, `time` as a quoted `$msec` string
- [ ] No reserved superset fields, no vhost, no usage comments in the file
- [ ] A parser-contract test proves a line in the shipped format parses into an Event, with `agent` reaching filters
- [ ] Ingest docs name the format "the bandage nginx log format" and point at the shipped snippet, with a "(flux-compatible)" migration note
- [ ] Parser comment and daemon config comment updated away from "flux log format"
