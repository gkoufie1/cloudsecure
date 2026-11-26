# Evidence: lab run of 26 November 2026

This folder holds real output from one deployment of the lab, not examples. Everything was collected on 2026-11-26 in `us-east-1`, against `lab.georgekoufie.xyz`.

**What was masked before publishing:** the AWS account ID (`<AWS_ACCOUNT_ID>`), the Cloudflare zone ID (`<CLOUDFLARE_ZONE_ID>`), and AWS resource IDs. Resource IDs keep their type and last four characters (for example `i-xxxxxxxxxxxxxdbd2`), so the same server can still be followed from file to file. Nothing else was changed. The API token used by the scanner appears in none of these files.

---

## 1. Baseline: everything secure

[`0-baseline.json`](0-baseline.json): combined AWS + Cloudflare scan. **7 PASS, 0 FAIL, 0 ERROR**, exit code `0`.

| Platform | Check | Result |
|---|---|---|
| AWS | IMDSv2 required | PASS (`required`) |
| AWS | No unrestricted inbound rules (lab security group) | PASS |
| AWS | No unrestricted inbound rules (VPC default security group) | PASS |
| AWS | Root disk encrypted | PASS |
| Cloudflare | Hostname is a proxied CNAME to the tunnel | PASS |
| Cloudflare | Minimum TLS version | PASS (`1.2`) |
| Cloudflare | Always Use HTTPS | PASS (`on`) |

## 2. Break-and-fix drill (IMDSv2)

IMDSv2 protects the instance metadata service, which hands out the server's temporary AWS credentials. With it turned off, a server-side request forgery (SSRF) bug in an app can be used to steal those credentials.

| Step | File | What it shows |
|---|---|---|
| Change request | [`drill-1-plan-break.txt`](drill-1-plan-break.txt) | Terraform plan: `0 to add, 1 to change, 0 to destroy`. One in-place change, `http_tokens = "required" -> "optional"` |
| Broken | [`drill-2-after-break.json`](drill-2-after-break.json) | Scanner: **IMDSv2 FAIL** (`optional`), the other 6 checks still PASS, exit code `1` |
| Exposure proven | [`drill-2-imds-test.txt`](drill-2-imds-test.txt) | On the server, a request with **no token** returns `200`, including the IAM credentials path |
| Fix request | [`drill-3-plan-fix.txt`](drill-3-plan-fix.txt) | Terraform plan: one in-place change back, `"optional" -> "required"` |
| Fixed | [`drill-4-after-fix.json`](drill-4-after-fix.json) | Scanner: **7 PASS**, exit code `0` |
| Fix proven | [`drill-4-imds-test.txt`](drill-4-imds-test.txt) | A request with no token now gets `401`, and one with a session token still gets `200`. The attack path is closed and legitimate access still works |

After the drill, `terraform plan` reported no changes, so the live infrastructure matched the committed code.

## 3. Edge and network tests

These were run from the lab server through SSM Run Command, because the tester's home ISP filter blocked the new domain (see *Lessons learned* in the main README). Results were recorded from the command output on the same day.

**Origin isolation**

| Test | Result |
|---|---|
| `https://lab.georgekoufie.xyz/health` | `200` with `server: cloudflare`, served over TLS 1.3 |
| The server's own public IP on port 8080 | no response: the origin can't be reached directly |
| `cloudflared` tunnel | 4 connections to 4 Cloudflare data centers (QUIC over UDP 7844) |

**Minimum TLS version** (`openssl s_client`, forcing each version)

| Version | Before | After setting TLS 1.2 minimum |
|---|---|---|
| TLS 1.0 | accepted | refused (`alert protocol version`) |
| TLS 1.1 | accepted | refused (`alert protocol version`) |
| TLS 1.2 | accepted | accepted |
| TLS 1.3 | accepted | accepted |

**WAF custom rule** for `/blocked-test`

| Request | Rule v1: path *equals* `/blocked-test` | Rule v2: `starts_with(lower(path), "/blocked-test")` |
|---|---|---|
| `/blocked-test` | 403 | 403 |
| `/blocked-test?x=1` | 403 | 403 |
| `/blocked-test/` | **404, got past the rule** | 403 |
| `/BLOCKED-TEST` | **404, got past the rule** | 403 |
| `/Blocked-Test/x` | not tested | 403 |
| `/%62locked-test` (URL-encoded) | not tested | 403 |
| `//blocked-test` | not tested | 403 |
| `/health`, `/api/transactions` | 200 | 200, normal traffic unaffected |
| `/blocked` | not tested | 404, correctly not blocked |

## 4. Scanner behaviour on a real permission error

The first combined scan used an API token that was missing *Zone Settings → Read*. The scanner recorded the two settings checks as **ERROR** (`403 Forbidden`) instead of passing them or crashing, and exited with code `2`. After the permission was added, the same checks passed. The token was also confirmed read-only: a write attempt was refused with `Unauthorized to access requested resource`.

## Screenshots

Screenshots from the same run are in [docs/screenshots](../screenshots/) and shown with captions in the main README's [Screenshots](../../README.md#screenshots) section.

## Not yet captured

- Actual AWS cost for the run (the README's cost table is still an estimate)
- Cloudflare Access login enforcement
