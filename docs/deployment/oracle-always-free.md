# Oracle Cloud Always Free: Plan and First Deployment

Status: plan for the provisioning gate (Stage B of the cloud workstream, [ADR-014](../architecture/adr/ADR-014-cloud-provider-oci-always-free.md)). Nothing is created until the account owner approves section 3. Related: [cloud-security-hardening.md](cloud-security-hardening.md), [operational-runbook.md](operational-runbook.md), [backup-and-restore.md](backup-and-restore.md), [../cloud/deployment-architecture.md](../cloud/deployment-architecture.md).

## 1. Rules

- **Budget: $0.** Only resources Oracle labels **Always Free** are created. No upgrade to Pay As You Go, no paid shape, no load balancer, no reserved public IP, no managed database, no paid monitoring, no storage above the allowance. A trial credit balance is not evidence that a resource is free, and a budget alert is not a spending cap.
- The **account owner** (an eligible adult) registers the account, verifies the payment card, accepts the agreements and clicks every console action that creates a resource. Nobody pastes OCI passwords, API keys or card details into a chat or a repository.
- No OCI API key or CLI credential is created for this project: everything in the console is done by the owner, and the VM is managed over SSH.
- If a resource cannot be confirmed as Always Free in the console (the "Always Free-eligible" label), the step stops.

## 2. Always Free allowance (checked 2026-10-14)

From Oracle's "Always Free Resources" page (docs.oracle.com, Free Tier) on 2026-10-14; check again on the day of provisioning, and check the account's own Limits page:

| Resource | Allowance | This plan uses |
|---|---|---|
| Ampere A1 compute (VM.Standard.A1.Flex) | 1,500 OCPU hours and 9,000 GB hours per month, equal to 2 OCPUs and 12 GB in total; in the home region | 1 instance, 2 OCPUs, 12 GB |
| Block and boot volume storage | 200 GB in total, home region; 5 volume backups | 1 boot volume of 50 GB |
| Outbound data transfer | 10 TB per month | well below |
| Networking | VCN, subnet, internet gateway, security list | 1 each (VCN components are free) |
| Public IPv4 | an ephemeral public IP on the instance's VNIC | 1 ephemeral (not reserved) |

Notes from the same page: Always Free compute and volumes must be in the **home region**; capacity can be unavailable ("out of host capacity"), in which case another availability domain may be tried; Oracle may **reclaim idle** Always Free instances (CPU, network and memory below 20 % at the 95th percentile over 7 days) (L-73).

## 3. The resource plan for approval

| Item | Value |
|---|---|
| Region | The tenancy's **home region** (shown in the console's region menu as "Home region"); not changed |
| Compartment | The root compartment or one new compartment `ciphermesh` (compartments are free) |
| VCN | `ciphermesh-vcn`, 10.0.0.0/16, created with the console's "VCN with internet connectivity" wizard (public subnet, internet gateway, route table); the NAT and service gateways the wizard offers for a private subnet are **not** needed and are not created if the wizard allows it |
| Subnet | Public subnet 10.0.0.0/24 |
| Security list (ingress) | TCP 22 from the operator's public IPv4 /32 only; TCP 80 and 443 from 0.0.0.0/0; ICMP type 3 code 4 (path MTU) as in the default list. Everything else removed |
| Security list (egress) | All TCP/UDP to 0.0.0.0/0 (package updates, Docker Hub, GitHub, npm, Let's Encrypt, DuckDNS); justified in [cloud-security-hardening.md](cloud-security-hardening.md) |
| Instance | `ciphermesh-vm`, shape **VM.Standard.A1.Flex**, **2 OCPUs, 12 GB** memory, image **Canonical Ubuntu 24.04** (aarch64, the "Minimal" variant is not required), any availability domain with capacity |
| Boot volume | 50 GB (default), in-transit encryption enabled if offered; no extra block volume |
| Public IP | Ephemeral public IPv4 assigned at creation (not reserved) |
| SSH key | The public key of a new ed25519 key pair made on the operator's workstation (`~/.ssh/ciphermesh_oci`); the private key never leaves the workstation |
| Monitoring | The instance's default (free) metrics only; no alarms or notifications that cost money |
| Expected charge | **$0**: every item above is Always Free or free networking |
| Uncertainties | Host capacity in the home region; the reclamation rule for idle instances; Oracle's terms can change |

Outside OCI, also free and owned by the account owner: two DuckDNS sub-domains (login with GitHub or another identity provider at duckdns.org), for example `cm-<name>.duckdns.org` and `cm-<name>-files.duckdns.org`, each pointing to the instance's public IPv4.

## 4. Account-owner steps (console)

1. Sign in to the OCI console; enable **MFA** for the user if it is not on (Identity, My profile). Capture EV-19-08 (redacted).
2. Check the home region and the Limits page for "VM.Standard.A1.Flex" (OCPU and memory limits greater than 0).
3. Create the VCN with the wizard (section 3).
4. Edit the public subnet's security list: remove the default SSH-from-anywhere rule only after adding the SSH rule for the operator's /32; add 80 and 443 from anywhere. Capture EV-17-02.
5. Create the instance (section 3), pasting the operator's SSH public key. Confirm the **Always Free-eligible** label next to the shape before clicking Create. Capture EV-17-01.
6. If the console reports "Out of capacity", try another availability domain once; otherwise stop and report (no retry loops, no paid shape).
7. Note the public IPv4 address; set both DuckDNS names to it.
8. Open the cost or usage page (Billing & Cost Management) and capture that no charges exist (EV-17-07). This is a record of the moment, not a guarantee.

## 5. Operator steps (SSH)

All commands run as the `ubuntu` user with `sudo`; the repository commit is the one approved for deployment.

```bash
# On the workstation
ssh -i ~/.ssh/ciphermesh_oci ubuntu@<public-ip>

# On the VM: a working copy of the operator scripts for the baseline
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/mhmmdimanquliyev7-dot/CipherMesh.git ~/ciphermesh && cd ~/ciphermesh && git checkout <commit>
sudo infrastructure/deployment/bin/cm-host-setup --operator ubuntu      # packages, Docker, SSH, timers
# Open a SECOND SSH session now and keep it open until the next step is verified.
sudo infrastructure/deployment/bin/cm-firewall apply any                # see cloud-security-hardening.md 2.3
sudo install -m 0644 infrastructure/deployment/cloud.env.example /srv/ciphermesh/config/cloud.env
sudo nano /srv/ciphermesh/config/cloud.env                              # host names, age recipient
sudo infrastructure/deployment/bin/cm-deploy <commit>                   # first run: installs the release
cd /srv/ciphermesh/release/infrastructure/deployment/bin
sudo ./cm-pki && sudo ./cm-secrets && sudo ./cm-tls placeholder
sudo ./cm-db-init < /dev/stdin                                          # paste the migrator password, then Ctrl-D
sudo ./cm-storage-init
sudo ./cm-deploy <commit>                                               # starts the stack
sudo ./cm-tls issue                                                     # Let's Encrypt for both names
sudo ./cm-status-collect
```

The migrator password is generated and kept on the workstation (`openssl rand -hex 32`, stored in the operator's password manager); it is typed into the session and never saved on the VM. The age identity for backups is generated on the workstation (`age-keygen -o ciphermesh-backup.key`); only its public line (`age1...`) goes into `cloud.env`.

## 6. Building the images

`cm-deploy` builds the three images natively on the VM (about 2 minutes for the API and 1 minute for the web image on the CI arm64 runner, longer on 2 OCPUs). The local equivalents, for a rehearsal on a workstation:

```bash
docker build -f infrastructure/docker/Dockerfile --target api -t ciphermesh-api:rehearsal .
docker build -f infrastructure/docker/Dockerfile --target ops -t ciphermesh-ops:rehearsal .
docker build -f infrastructure/docker/Dockerfile --target web --build-arg CM_STORAGE_ORIGIN=https://files.localhost:8443 -t ciphermesh-web:rehearsal .
infrastructure/deployment/bin/cm-rehearsal up
```

## 7. Verification after the first deployment

1. From the workstation: `node scripts/cloud/edge-check.mjs --app https://<app host> --files https://<files host>` (EV-17-04, EV-18-04, EV-19-05).
2. `CM_SMOKE_APP_ORIGIN=https://<app host> pnpm exec playwright test -c playwright.deployment.config.ts cloud-smoke` (EV-17-08).
3. On the VM: `cm-tls renew-test` (EV-19-12), then set `CM_HSTS_MAX_AGE=86400` and run `cm-deploy <commit>` again.
4. Platform administrator: register the account in the browser, enroll MFA, then on the VM `docker compose ... run --rm --no-deps api dist/platform-admin.js grant <email>` (operational-runbook.md section 4); open the security dashboard (EV-19-11).
5. Run the hardening evidence of [cloud-security-hardening.md](cloud-security-hardening.md) section 3 and the backup and restore drill (EV-19-07).

## 8. If something goes wrong

- **Capacity:** report "ORACLE CLOUD PROVISIONING: BLOCKED, FREE CAPACITY UNAVAILABLE"; the local rehearsal remains the fallback demonstration and is labelled as such.
- **Lockout:** the OCI console's instance console connection (serial console, free) gives access without SSH; the security list can be edited in the console.
- **A charge appears:** stop and terminate the resource that causes it, then report; never "fix" it with another paid resource.
