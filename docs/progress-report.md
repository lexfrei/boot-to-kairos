# Progress report

Past the point of no return ssh stops answering, so the install can report its progress over HTTP instead. `--report-url URL` posts it to an `http` or `https` endpoint, one JSON object per report, until the reboot. `--report-ca FILE` trusts the CA certificates in that PEM file for an `https` endpoint, instead of the system's. A user and password in the URL are sent as basic auth. The plan and the log show the URL without them and without its query, but with its path, so a token belongs in the query.

```json
{"version":1,"run":"9f2c6d0b8a4e4f1c9e3a7b5d2c1f0e8a","seq":7,"time":"2026-10-18T09:12:44.512Z","hostname":"node1","disk":"/dev/sda","phase":"writing","bytes":{"done":2147483648,"total":21474836480,"attempt":1}}
```

`run` is new for each run, and `seq` counts its reports from 1.

| `phase` | Sent when | Extra fields |
| --- | --- | --- |
| `started` | reporting starts | |
| `planned` | the disk image is built | the plan, as in [JSON output](dry-run-and-json-output.md#json-output) |
| `dry-run` | a dry run ends | the whole plan |
| `quiesced` | the target disk is quiesced | |
| `writing`, `verifying` | for the write and the read-back of each attempt: after the first chunk, at the end, and every 5% or 10 seconds between | `bytes` |
| `verified` | an attempt passed | its `bytes` and `repairs` |
| `synced` | the other disks are flushed | |
| `rebooting` | right before the reboot | |
| `refused` | the run stopped before the point of no return | `error` with `class` and `message` |
| `failed` | the run failed after it, except when the reboot itself fails | `error` |

Some refusals come before reporting starts and are not reported: a bad flag, the disk, a cloud-config that cannot be read or does not start with `#cloud-config`, and `already-running`. Neither the cloud-config nor any key is reported, and the plan names SSH host keys by fingerprint only. A refusal's message is the one stderr gets. For a cloud-config that does not decode, it may quote a few characters of the bad value.

## Delivery

Reporting never stops or holds up the install.

- The endpoint's name is resolved and its CA certificates are loaded before anything is built. Reports then go to the addresses resolved then, through no proxy, and a redirect is not followed. A name that does not resolve costs a warning, and the plan says why nothing is reported.
- An address in the URL is used as it is, and a link-local one keeps its zone, written `%25` in the URL: `http://[fe80::1%25eth0]:8080/`.
- Reports queue and are sent one at a time, each once, with a 3 second timeout. An answer other than 2xx counts as a failure. The first failure is logged, and the run goes on.
- A report that does not fit in the queue is dropped, which shows as a gap in `seq`. `writing` and `verifying` leave the last places in the queue to the other phases.
- Before the reboot or the exit, the reports still queued get 5 seconds in all, and the log says how many were delivered.
- A dry run reports too, so it can test the endpoint.

[`contrib/report-receiver.py`](../contrib/report-receiver.py) prints each report on a line of its own. Run it as `python3 contrib/report-receiver.py --port 8080`, and add `--cert` and `--key` for https.
