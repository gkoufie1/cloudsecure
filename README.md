# CloudSecure: a locked-down web server on AWS, behind Cloudflare

[![CI](https://github.com/gkoufie1/cloudsecure/actions/workflows/ci.yml/badge.svg)](https://github.com/gkoufie1/cloudsecure/actions/workflows/ci.yml)

CloudSecure is a small security lab. It puts a web server on AWS that **nobody on the internet can connect to directly**, publishes it safely through Cloudflare, and then uses a Python scanner to **prove** the security settings are in place, writing the results to a report an auditor could read.

It's built to show how security work is done in practice: infrastructure written as code, every admin action logged, trade-offs written down, and evidence that's honest about what it does and doesn't prove.

> This is a learning lab, not a PCI compliance certification. It uses no real card data. Run it in a dedicated AWS account and a dedicated Cloudflare test domain.

---

## What this project shows

- **The server has zero open inbound ports.** No SSH, no HTTP, nothing. Its firewall (security group) has no inbound rules at all, yet the website still works.
- **Admins get in without SSH keys.** Access goes through AWS Systems Manager (SSM), is controlled by IAM, and every session is recorded.
- **Security is checked across two platforms at once.** The scanner reads AWS and Cloudflare settings and puts both in one evidence report.
- **"Couldn't check" is never reported as "passed."** If the scanner can't read a setting, it says so.
- **Changes are deliberate and reviewable.** Everything on AWS is Terraform, and a practice drill shows a control breaking and being fixed, with evidence before and after.
- **The pipeline protects itself.** CI scans the infrastructure code, runs tests, and is hardened against supply-chain attacks.

**Skills used:** Terraform · AWS (VPC, EC2, IAM, Systems Manager, CloudWatch) · Cloudflare (Tunnel, WAF, Access) · Python with boto3 · GitHub Actions · Checkov · PCI DSS v4.0 control mapping

---

## How it works

```mermaid
flowchart LR
    user(["Visitor"])
    admin(["Admin"])
    scanner["Scanner<br/>(read-only)"]
    evidence[("Evidence report<br/>PASS / FAIL / ERROR")]

    subgraph CF["Cloudflare"]
        edge["HTTPS only · TLS 1.2+<br/>Web firewall · Login check"]
        tunnel["Tunnel"]
    end

    subgraph AWS["AWS private network (VPC)"]
        subgraph EDGE["Public subnet: outbound traffic only"]
            ec2["Server<br/>no inbound ports<br/>encrypted disk"]
            app["Demo app<br/>(only reachable<br/>from the server itself)"]
            cfd["Tunnel connector"]
        end
        iso["Isolated subnet<br/>(empty, no internet)"]
        logs[("Logs<br/>network traffic<br/>admin sessions")]
    end

    ssm["AWS Systems Manager"]

    user -->|HTTPS| edge --> tunnel
    cfd -->|"connects out"| tunnel
    cfd --> app
    admin --> ssm
    ec2 -->|"connects out"| ssm
    ec2 -.-> logs
    ssm -.-> logs
    scanner --> AWS
    scanner --> CF
    scanner --> evidence
```

The key idea is that **every connection starts from inside the server and goes out.** Nothing on the internet can start a connection in.

**When a visitor opens the site:** their browser connects to Cloudflare, not to AWS. Cloudflare enforces HTTPS, blocks attacks with its web application firewall (WAF), and can require a login. Only then does it pass the request down a tunnel. That tunnel was opened *from* the server by a small program called `cloudflared`, a bit like the server phoning Cloudflare and keeping the line open. The request comes back down that line to the demo app.

**When an admin needs to log in:** they use AWS Systems Manager instead of SSH. The SSM agent on the server also connects outward to AWS, so there's no port 22 to attack and no key files to lose. Who can log in is controlled by IAM, and every session is saved to CloudWatch logs.

**When the scanner runs:** it uses read-only API calls to check AWS and Cloudflare settings, then writes a JSON report with a timestamp.

---

## What gets checked

| Check | In plain words | How it's verified | PCI DSS v4.0 |
|---|---|---|---|
| No open inbound rules | Nothing on the internet can reach the server directly | Scanner | Req. 1 |
| Default firewall locked down | The VPC's built-in "default" security group allows nothing | Terraform + Security Hub | Req. 1 |
| Traffic only via the tunnel | The website's DNS points at the Cloudflare tunnel and is proxied | Scanner | Req. 1 |
| IMDSv2 required | Blocks a common trick for stealing AWS credentials from a server | Scanner | Req. 2 |
| Encrypted disk | The server's storage is encrypted | Scanner | Req. 3 |
| Modern TLS only | Cloudflare refuses connections older than TLS 1.2 | Scanner | Req. 4 |
| HTTPS forced | Plain HTTP visitors are redirected to HTTPS | Scanner | Req. 4 |
| Web firewall rules | Cloudflare WAF blocks known attacks and a test path | Manual (dashboard) | Req. 6 |
| Login with MFA | Cloudflare Access requires a verified login | Manual (identity provider) | Req. 8 |
| Logging | Network traffic and admin sessions are logged | CloudWatch | Req. 10 |

The full mapping, including the limits of each check, is in [compliance/controls.csv](compliance/controls.csv).

### What the report looks like

Every check gets one of four results:

- **PASS:** the setting is correct
- **FAIL:** the setting is wrong
- **ERROR:** the scanner couldn't check it (for example, a missing permission). This is *not* a pass.
- **NOT_TESTED:** the check was skipped (for example, no Cloudflare details were given)

An example of the format:

```json
{
  "timestamp": "2026-11-25T14:00:00+00:00",
  "region": "us-east-1",
  "vpc": "vpc-0123456789abcdef0",
  "findings": [
    {"platform": "AWS", "resource": "i-0abc...", "control": "IMDSv2", "status": "PASS", "evidence": "required"},
    {"platform": "Cloudflare", "resource": "zone-id", "control": "min_tls_version", "status": "ERROR",
     "evidence": "HTTPError: 403 Forbidden"}
  ]
}
```

The scanner's exit code tells scripts what happened: `0` everything checked passed, `1` something failed, `2` something couldn't be checked.

---

## Why it's built this way

Every design involves trade-offs. These are the main ones, and what would change in a real production setup.

**Cloudflare Tunnel instead of a load balancer.** A load balancer needs an open port, and an open port gets scanned and probed all day. With a tunnel there's simply nothing to attack from the outside, and bad traffic is filtered at Cloudflare before it ever reaches AWS. *In production* with several servers, an AWS load balancer in private subnets that only accepts Cloudflare traffic would also work.

**Systems Manager instead of SSH.** SSH means an open port 22 and key files that get copied, shared and forgotten. SSM removes both, ties access to IAM, and records every session, which is exactly the audit trail compliance asks for.

**A public IP address, but outbound only.** The textbook design hides the server in a private subnet behind a NAT gateway, but a NAT gateway costs about $32 a month, more than the rest of the lab put together. A public IP doesn't open anything by itself; the firewall decides what gets in, and here the answer is nothing. The honest downside is less defense in depth: if someone later added a bad firewall rule, the server would be exposed. *In production:* private subnets, a NAT gateway or egress firewall, and private VPC endpoints for AWS services.

**Cloudflare is set up by hand, not in Terraform.** Terraform saves everything it manages in a "state" file, including secrets, in plain text. Keeping Cloudflare out of Terraform means the tunnel's secret token never lands in a file or in this repo. *In production:* manage Cloudflare in Terraform too, with encrypted remote state and the token in a secrets manager.

**The scanner reports errors instead of crashing.** The first version crashed on any error and wrote nothing. Worse, a skipped check could look like a pass. Now each check stands alone, errors are recorded as errors, and the report is always written.

**The server image is pinned.** Amazon releases a new Linux image every few weeks. Without pinning, Terraform would quietly plan to delete and rebuild the server after each release. Upgrades are now a deliberate command, not a surprise.

**Basic log encryption and 90-day retention.** Logs are encrypted with AWS-managed keys and kept for 90 days to keep costs down. PCI expects 12 months, which is a one-line change (`log_retention_days = 365`). These exceptions are written into the code as documented Checkov skips, each with its reason, so nothing is hidden and any *new* problem still fails the build.

---

## What this is not

Being clear about limits is part of doing security honestly.

- **Not a PCI certification.** It shows how controls map to PCI requirements. It doesn't prove compliance.
- **Not fully private or highly available.** It's one server in one availability zone, with a public IP for outbound traffic.
- **Not end-to-end encrypted to the app.** Traffic is encrypted up to the server. The last step from the tunnel connector to the app is plain HTTP, but it never leaves the machine.
- **Not a replacement for real scanners.** Tools like Prowler and AWS Security Hub run hundreds of checks. This scanner runs a focused handful and is built to show how evidence should be collected and reported.

---

## Run it yourself

### What you need

- A **dedicated** AWS account (not one used for anything real)
- A test domain already active on Cloudflare
- A machine with Terraform 1.6+, AWS CLI v2, Python 3 and `python3-venv`
- AWS access through temporary credentials or an admin role. **Never use root account keys.**
- An AWS Budget alert, so you get an email if spending climbs. (A budget is an alert, not a hard cap.)

### 1. Build the AWS side

```bash
cd terraform
terraform init
terraform plan -out=lab.tfplan
terraform apply lab.tfplan
terraform output
```

Give it a few minutes for the server to start and register with Systems Manager. Note the `instance_id`, `vpc_id` and `region` from the output.

> **If apply fails with `DocumentAlreadyExists`:** your account already has Session Manager settings. Either import them with `terraform import 'aws_ssm_document.session_prefs[0]' SSM-SessionManagerRunShell`, or skip managing them with `-var manage_session_manager_preferences=false`. Be aware that `terraform destroy` removes these settings for the whole region.

### 2. Connect Cloudflare

1. Open a session on the server: AWS console → Systems Manager → Session Manager, or `aws ssm start-session --target INSTANCE_ID`.
2. Check the app is running: `curl http://127.0.0.1:8080/health` should return `{"status": "ok"}`.
3. In Cloudflare, go to **Networking → Tunnels** and create a tunnel. Pick Linux x86_64 and the Amazon Linux (RPM) instructions, and run the install command inside your SSM session. **The tunnel token is a secret. Never commit it or paste it anywhere public.**
4. Add a route from your test hostname (e.g. `lab.example.com`) to `http://localhost:8080`.
5. If you want the demo private, protect the hostname with **Cloudflare Access** before you publish it.

### 3. Turn on the edge protections

In your test domain's Cloudflare settings:

- Set the minimum TLS version to 1.2 or higher, and turn on Always Use HTTPS
- Turn on the managed WAF rules available on your plan
- Add a custom WAF rule that blocks the path `/blocked-test`, then confirm with `curl` that it's blocked
- Set up Access with your identity provider and confirm that a browser that isn't logged in gets turned away

Never change these settings on a domain that's used for anything real.

### 4. Run the scanner

From the top folder of the repo:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
mkdir -p evidence

# AWS checks only
python scanner/audit.py --region REGION --vpc VPC_ID --output evidence/baseline.json
```

`--region` must match the region you deployed to (it defaults to `us-east-1`).

To include the Cloudflare checks, create a Cloudflare API token with only **DNS Read** and **Zone Settings Read** for the test domain, then:

```bash
read -rs CLOUDFLARE_API_TOKEN; export CLOUDFLARE_API_TOKEN   # paste the token; it won't show on screen
python scanner/audit.py --region REGION --vpc VPC_ID \
  --zone ZONE_ID --hostname lab.example.com --output evidence/combined.json
```

The scanner only needs read-only permissions (EC2 `Describe*` on AWS).

### 5. Practice a break-and-fix drill

This is how you produce real before-and-after evidence:

1. In `terraform/main.tf`, change `http_tokens = "required"` to `"optional"`. This turns off IMDSv2 protection.
2. Run `terraform plan`, save the plan as your "change request", and apply it.
3. Scan again. The IMDSv2 check should now **FAIL**.
4. Change it back to `"required"`, apply, and scan once more. It should **PASS**.
5. Compare the three reports.

Only do this on the lab server, and never open inbound access as part of a test.

### 6. Clean up when you're done

1. In Cloudflare: delete the route and DNS record, the Access application and the tunnel, and revoke the API token.
2. In the `terraform` folder: run `terraform destroy`.
3. In the AWS console, confirm that the server, disk, public IP and VPC are gone.

Security services you turned on by hand at the account level (like Security Hub) aren't removed by Terraform and may keep billing.

### Good to know

- **Updating the server image:** the image is pinned on purpose. To move to the latest Amazon Linux, run `terraform apply -replace=aws_instance.origin`.
- **Editing `bootstrap.sh`** (the server's startup script) rebuilds the server on the next apply, because the script only runs on first boot.

---

## Cost

These are rough estimates for running 24/7 in `us-east-1` at on-demand prices, before any free tier. Check your own bill.

| Item | About |
|---|---|
| t3.micro server | $7.60 / month |
| Public IPv4 address | $3.65 / month |
| 8 GB encrypted disk | $0.65 / month |
| CloudWatch logs (light lab traffic) | under $1 / month |
| Cloudflare Tunnel and Access (free plan, small team) | $0 |
| **Total** | **about $12 / month** |

The biggest saving is skipping the NAT gateway, which alone would be about $32 a month. Run `terraform destroy` when you're not using the lab and the cost drops to nothing.

---

## Automated quality checks

Every push and pull request runs these checks in [GitHub Actions](.github/workflows/ci.yml):

- **Terraform format and validation:** the infrastructure code is valid and tidy
- **Checkov:** scans the Terraform for security misconfigurations. Accepted lab trade-offs are skipped *in the code with a written reason*, so any new issue fails the build.
- **Unit tests:** 14 tests for the scanner, with AWS and Cloudflare simulated, so no real credentials are needed
- **ShellCheck:** catches bugs in the server's startup script

The pipeline itself is hardened against supply-chain attacks, where an attacker tampers with a tool or library your build downloads:

- Every GitHub Action is pinned to an exact commit, so it can't be swapped out behind a version tag
- Python packages install from [requirements-lock.txt](requirements-lock.txt), with exact versions and checksums, using prebuilt packages only, so no install scripts run

Run the tests on your own machine with `python -m unittest discover -s tests -v`. If you change `requirements.txt`, regenerate the lock file:

```bash
uv pip compile requirements.txt --python-platform x86_64-unknown-linux-gnu --python-version 3.12 --generate-hashes --only-binary :all: -o requirements-lock.txt
```

---

## Project layout

```
terraform/main.tf          AWS network, server, firewall, logging, IAM roles
terraform/bootstrap.sh     Startup script that installs the demo app on the server
scanner/audit.py           Evidence scanner for AWS and Cloudflare
tests/test_audit.py        Unit tests for the scanner
compliance/controls.csv    Checks mapped to PCI DSS requirements, with limitations
.github/workflows/ci.yml   Automated quality and security checks
```

---

## What I'd add next

- 12-month log retention with customer-managed encryption keys
- Private subnets with controlled outbound traffic, and private endpoints for AWS services
- A private, encrypted database with its own firewall rules, separate from the app
- AWS Config, Security Hub, Inspector and CloudTrail checks in the scanner
- Automated checks for the Cloudflare WAF and Access settings, which are manual today
- Remediation that needs approval before it runs

---

## References

- [Cloudflare Tunnel: getting started](https://developers.cloudflare.com/tunnel/get-started/)
- [Cloudflare Tunnel tokens](https://developers.cloudflare.com/tunnel/reference/tunnel-tokens/)
- [PCI DSS document library](https://www.pcisecuritystandards.org/document_library/)
