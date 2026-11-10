# Container Config Auditor

This tool audits the JSON configs of containers that run **untrusted, customer-written scripts**. It reports every risky setting with its **severity**, the **reason** it is risky and a **safer setting**. The exit code lets a CI pipeline block a risky config.

It uses only the Python standard library: no Docker, no network calls and no dependencies.

## Run it

You need Python 3.11 or newer. Run these from the project root:

```bash
python3 -m auditor examples/unsafe.json                 # readable report
python3 -m auditor examples/mixed.json --format json    # machine-readable
python3 -m auditor examples/safe.json --fail-on medium  # stricter CI gate
python3 -m unittest -v                                  # run the tests
```

The input file holds one config object or a list of them:

```json
{
  "container_name": "customer-script-01",
  "privileged": true,
  "run_as_root": true,
  "read_only_root_filesystem": false,
  "network_enabled": true,
  "mounts": ["/var/run/docker.sock"]
}
```

| Exit code | Meaning |
|---|---|
| `0` | No finding at or above the `--fail-on` threshold (default `high`) |
| `1` | At least one finding at or above the threshold |
| `2` | The file couldn't be read, or isn't valid JSON or a valid config list |

## What it checks

| ID | Risk | Severity | Safer setting |
|---|---|---|---|
| R1 | `privileged: true` | CRITICAL | `privileged: false`; drop all capabilities and add back only those needed |
| R2 | `run_as_root: true` | HIGH | Run as an unprivileged user (`USER 1000`) |
| R3 | `read_only_root_filesystem: false` | MEDIUM | `--read-only` plus `--tmpfs /tmp` |
| R4 | Docker socket mounted, **even read-only** | CRITICAL | Remove the mount |
| R5 | Network on without a valid allowlist | HIGH | Network off, or allow only named hosts |
| R5a | Cloud metadata address in the allowlist | HIGH | Remove the entry |
| R5-ok | Network limited to named hosts | INFO | Compliant; no change needed |

Each container gets a grade:
- **FAIL** if any finding is HIGH or CRITICAL.
- **REVIEW** if the worst finding is MEDIUM or LOW.
- **PASS** otherwise.

**Severity basis.** The tools I compared don't agree on one scale: Kubernetes Pod Security Standards, CIS, Trivy, Prisma and Kubesec. I chose levels from the range they give, leaning strict because the code is untrusted.
- Root is HIGH, where most scanners say MEDIUM.
- The socket mount is CRITICAL, where Datadog and Prisma say MEDIUM.

| Setting | K8s Pod Security | Trivy | Prisma (Checkov) | Kubesec | Chosen |
|---|---|---|---|---|---|
| Privileged | forbidden at Baseline | HIGH | HIGH | Critical | CRITICAL |
| Docker socket | Baseline bans hostPath | HIGH | MEDIUM | Critical | CRITICAL |
| Root user | forbidden at Restricted | MEDIUM–HIGH | MEDIUM | advise | HIGH |
| Writable root FS | not covered | HIGH | LOW | advise | MEDIUM |

## Network policy

> Customer scripts are untrusted. Outbound network access is denied by default. It is allowed only when `egress_allowlist` names the specific destinations the script needs. A missing, empty or invalid allowlist, or one that allows everything (`*`, `0.0.0.0/0`), counts as no allowlist.

Network access is **not** treated as automatically unsafe. Many scripts legitimately call an API, and NIST SP 800-190 asks for container egress to be *controlled*, not banned. So network on with a named allowlist is reported as INFO and passes.

## Assumptions

- **`egress_allowlist` is an optional field I added.** The assignment's example doesn't have one, and without it the auditor couldn't tell a safely networked container from an unsafe one. If the field is absent and the network is on, the result is R5.
- **`mounts` entries** are host paths, as in the example (`"/var/run/docker.sock"`). The form `host:container[:ro]` is also accepted, and only the host part is checked.
- **Missing or wrongly typed settings fail closed.** A missing `privileged`, or `"false"` written as text, is reported as "cannot verify". It gets the severity of the rule it blocks (CWE-636, "Failing Open").

## Edge cases and how they're handled

| Input | Result | Why |
|---|---|---|
| A required setting is missing | `V-<key>` finding, same severity as its rule | Otherwise a config could leave out every dangerous key and pass |
| `"false"`, `0` or `null` instead of `true`/`false` | `V-<key>`, never coerced | In Python the text `"false"` counts as true |
| An entry in the list isn't an object (e.g. `42`) | `V-shape` (CRITICAL) for that entry; the others are still audited | One bad entry must not hide the rest |
| Socket mounted read-only (`/var/run/docker.sock:/sock:ro`) | R4 | `:ro` stops writes to the file, not API calls through it |
| Socket path written another way: `/run/docker.sock`, `/var/run/../run/docker.sock`, `/var/run/`, a Docker Desktop path | R4 | Paths are normalised, and any file named `docker.sock` matches. `/var/run` is a symlink to `/run`. |
| A folder that holds the socket: `/`, `/run`, `/var/run` | R4 | The socket is reachable inside it |
| Allowlist is `null`, not a list, empty, or has a blank entry | R5 | An invalid allowlist counts as none |
| Allowlist contains `*`, `0.0.0.0/0` or `::/0` | R5 | A match-all entry allows everything |
| Allowlist contains `169.254.169.254`, `fd00:ec2::254` or `metadata.google.internal` (any spelling that contains them) | R5a | The metadata service hands out the host's cloud credentials |
| Network off, but the allowlist is bad | No finding | The allowlist only matters when the network is on |
| File missing, not JSON, empty list, or a bare number or string | Error message, exit code 2 | There's nothing valid to audit |

## Trade-offs and limitations

The auditor is deliberately strict. It fails on missing settings, flags read-only socket mounts, catches socket paths written differently (`/run/docker.sock`, `/var/run`, `..`), and ranks root above most scanners. That can mean extra failures on older configs, but a false alarm costs far less than a missed host takeover. `--fail-on` lets teams loosen the gate.

It is a **static, point-in-time check of the config file**, not of the running container. It can't detect drift after deployment. NIST notes that such scans need runtime enforcement alongside them. For untrusted code, the real defence is layered:
- seccomp and AppArmor profiles,
- user-namespace remapping or rootless Docker,
- a sandboxed runtime such as gVisor.

None of these is checked here.

Allowlist entries are checked by their text only. The tool doesn't resolve DNS, catch every encoding of the metadata IP, or verify that a host is who it claims to be.

Not covered:
- capabilities and `no-new-privileges`
- resource limits
- host network and PID namespaces
- other sensitive host mounts (`/etc`, `/proc`)
- image provenance
- secrets

The structure makes these cheap to add. A new yes/no check is one row in `rules/settings.py`. Any other check is one function plus one line in `rules/__init__.py`.

## Project layout

```
auditor/          the program (python -m auditor)
  rules/          one module per kind of check, registered in RULES
tests/            one test module per program module
examples/         safe.json, unsafe.json (the assignment's example), mixed.json
```

## Sources

Each finding in the report lists the tags of the sources it relies on.

| Tag | Source |
|---|---|
| OWASP-CS | [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) (`#n` = rule number) |
| OWASP-DG | [OWASP Developer Guide: container security](https://devguide.owasp.org/12-appendices/01-implementation-dos-donts/01-container-security) |
| OWASP-SCP | [OWASP Secure Coding Practices checklist](https://owasp.github.io/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist) |
| OWASP-SSRF | [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) |
| CWE-636 | [CWE-636: Not Failing Securely ("Failing Open")](https://cwe.mitre.org/data/definitions/636.html) |
| Netdata | [Netdata: Docker socket security](https://www.netdata.cloud/guides/docker/docker-socket-security/) |
| DD-CIS531 | [Datadog: containers should not mount the Docker socket (CIS 5.31)](https://docs.datadoghq.com/security/default_rules/cis-docker-1.2.0-5.31/) |
| TEN-CIS | [Tenable audit items for the CIS Docker Benchmark](https://www.tenable.com/audits/) |
| DOCK-POST | [Docker: Linux post-installation steps](https://docs.docker.com/engine/install/linux-postinstall/) |
| DOCK-USERNS | [Docker: isolate containers with a user namespace](https://docs.docker.com/engine/security/userns-remap/) |
| K8S-PSS | [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) |
| K8S-NP | [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) |
| NIST-190 | [NIST SP 800-190, Application Container Security Guide](https://doi.org/10.6028/NIST.SP.800-190) |
| NIST-GLOSS | [NIST glossary: "deny by default"](https://csrc.nist.gov/glossary/term/deny_by_default) |
| Vercel | [A sandbox without a network boundary is only half a sandbox](https://vercel.com/blog/a-sandbox-without-a-network-boundary-is-only-half-a-sandbox) |
| Blaxel | [Sandbox egress control and outbound allow-listing](https://blaxel.ai/blog/sandbox-egress-control-outbound-allow-listing) |
| AWS-EKS-IAM | [AWS EKS Best Practices: identity and access management](https://docs.aws.amazon.com/eks/latest/best-practices/identity-and-access-management.html) |
| AWS-IMDS | [AWS: Instance Metadata Service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) |
| GCP-MD | [Google Cloud: VM metadata](https://docs.cloud.google.com/compute/docs/metadata/overview) |
| AZ-IMDS | [Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service) |
