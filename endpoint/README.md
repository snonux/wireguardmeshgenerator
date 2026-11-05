# Endpoint-only migration preparation (conf p24)

Preparation, **not deployed**. No actual input YAML, key, generated config or
endpoint has been changed. Native disconnected expiry/reboot, fresh management,
handshake/traffic, overlay v4/v6 and service/cold-start acceptance remain later
migration gates (conf y14 and subsequent stages).

This tool handles one approved destination and one referring host per apply.
It patches exactly one Endpoint by public peer identity in the current saved
configuration, and uses `wg set wg0 peer … endpoint …` for the runtime delta.
It never runs generation, clean, install, setconf, syncconf, wg-quick, interface
restart, key generation, route mutation, or an entire stale-config restore.
It accepts only the approved old 192.168.1.N:56709 → 10.20.0.N:56709 map.
Public gateways, all identities/keys/PSKs, peer sets, AllowedIPs, keepalives,
overlay addresses and interface settings must compare equal. Duplicate peer
identities, unknown directives and ambiguous syntax fail closed. Repeated
Address/DNS/AllowedIPs and disabled keepalives are understood. Only referring
FreeBSD f-hosts and Rocky r-nodes use the helper; it does not migrate NetBSD's
tun0, guest address plans, public gateways, wg1 or the controller network.

## Address coordination boundary

Finish and independently confirm the destination's m14/n14 address transaction
**first**, with both old/new addresses retained. Prove fresh authenticated old
and new access, return routing and UDP56709 from every referring host. Do not
retire either destination address while this endpoint transaction is pending.
The destination address rollback journal must already be accepted/archived,
so its timer cannot withdraw the new address halfway through endpoint release.

The endpoint helper deliberately rejects m14/n14 destination-local hook paths
(`…/gonf-network-migration/pending/endpoints`). Do not set their
`endpoints-required` flag for this procedure. A destination hook cannot restore
endpoint journals stored on remote referring hosts or a disconnected controller.
If an address transaction must include endpoint changes, this tool does **not**
authorize it: redesign/extend that protocol separately. With this staged
procedure, address failure leaves old management available and each referring
host independently restores its own saved and running endpoint. No source
promotion occurs until the destination and **all** referring hosts accepted.

## Dormant installation and activation prerequisites

Do not install or enable this during p24 preparation. Later authorized work
must provision Python **3.9+** explicitly: `/usr/bin/python3` on Rocky and
`/usr/local/bin/python3` on FreeBSD. The shebang uses env, so installed service
PATH must select that verified interpreter. Ruby is needed only on the controller
(the existing generator's YAML parser); there are no new Python dependencies.

Install `endpoint.py` as root-owned executable
`/usr/local/sbin/gonf-endpoint-rollback` and a root-owned mode-0600 scope config
at `/usr/local/etc/gonf-endpoint.json`. Create a root-owned 0700 state parent
and `pending` directory at `/var/lib/gonf-endpoint` (Rocky) or
`/var/db/gonf-endpoint` (FreeBSD). Do not replace a pending scope/config/journal.
The config is a JSON object with these fields (public fixture identity only):

```json
{
  "id": "unique-destination-stage-id",
  "role": "peer",
  "interface": "wg0",
  "peer": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
  "old": "192.168.1.120:56709",
  "new": "10.20.0.120:56709",
  "source_sha256": "SHA256_OF_EXACT_CURRENT_SOURCE_BYTES",
  "saved": "/etc/wireguard/wg0.conf",
  "wg": "/usr/bin/wg"
}
```

FreeBSD uses `/usr/local/etc/wireguard/wg0.conf` and `/usr/local/bin/wg`.
The public identity must be the actual **destination** identity, checked against
the saved and running referring configurations, never inferred from a hostname.
A SHA256 receipt binds the same source/scope across the controller and hosts.
No configuration/key output is printed; receipts include only phase/deadline and
scope digest. All journal backups contain secrets and stay mode 0600 under 0700
parents, outside git; never attach their contents to task notes.

Rocky: install `linux/*` under `/etc/systemd/system`, then, only during later
authorized activation, reload PID1 and enable the boot/runtime units plus
`gonf-endpoint-rollback.timer` (start the timer). Persistent restore precedes
`wg-quick@wg0`; runtime restore follows it and is required before k3s. Verify
that this matches the host's actual wg0 startup unit, SELinux policy and k3s
ordering. A host with another startup service is unsupported until its ordering
is reviewed. Snapshot refuses inactive timer or disabled boot/runtime units.
The 15-second timer retries failed expiry restoration. Wall-clock changes can
shift the 900-second deadline; include that in native canary review.

FreeBSD: install `freebsd/rc-rollback` as `/etc/rc.d/gonf_endpoint_rollback` and
`freebsd/rc-runtime` as `/etc/rc.d/gonf_endpoint_runtime`, root-owned 0755.
The early system rc.d hook restores persistent state before netif/wireguard;
the second restores runtime after wireguard, before LOGIN. Install this exact
root-crontab **system** line (in `/etc/crontab`), with cron running:

```cron
* * * * * root /usr/local/sbin/gonf-endpoint-rollback watchdog /var/db/gonf-endpoint/pending
```

Snapshot checks cron and native rcorder ordering. rc.d failure alone does not
halt all FreeBSD boot scripts; verify saved-config restoration and retry behavior
in the native canary before relying on it. No reboot command is provided.

Before provisioning `pending/recovery-approved`, prove independent expiry with
SSH gone, idempotent restoration, confirm/release, unconfirmed boot before wg0
loads, runtime restoration afterwards and reapply behavior, using a bounded
native canary. Each authorization file is root-owned 0600 and contains exactly
the current unique transaction ID. This is an explicit operator assertion of
external proof, not a test result produced by this tool. No recipe creates it.

## Controller procedure

Keep the repository on persistent local storage. A private 0700 controller
state directory outside git owns its manifest and source snapshots. Do not use
`keys/` or `dist/`. Prepare a **private** YAML candidate by changing only this
destination's `hosts.<destination>.lan.ip`; never regenerate configurations to
construct the delta. `begin` uses the generator's native Ruby YAML parser to
refuse every other semantic source difference, and verifies the source digest.

Prepare a private JSON manifest with `destination`, `scope` (the five common
fields `id`, `peer`, `old`, `new`, `source_sha256` from the host config), and an
explicit `peers` map. Include **every** currently persisted referring host for
this destination, checked against current private configs and the sanitized
endpoint inventory. Each referring entry has trusted SSH argv, noninteractive
privilege prefix, and the fixed host journal path, for example:

```json
{"ssh": ["ssh", "-oBatchMode=yes", "-p", "22", "operator@b.example"],
 "prefix": ["sudo", "-n"], "journal": "/var/lib/gonf-endpoint/pending"}
```

FreeBSD can use `["doas", "-n"]`. SSH argv is operator-trusted input; configure
connection timeouts and independently working literal management destinations.
The controller quotes the fixed remote helper/action/path; it suppresses command
errors so no private command output enters logs. It does not discover hosts or
invent reachability results.

In the private state directory create mode-0600 `destination-approved.json`:

```json
{"id": "unique-destination-stage-id", "destination": "a.example",
 "dual_address_accepted": true, "old_address_retained": true,
 "referring_hosts": ["b.example", "c.example"]}
```

The sorted referring list must exactly match the manifest. Create this assertion
only after verifying the address gates and inventory above. Example command
sequence (paths are operator inputs; these commands are **not** run by p24):

```sh
python3 endpoint/controller.py begin --repo REPO --state PRIVATE_STATE --manifest MANIFEST --candidate CANDIDATE
python3 endpoint/controller.py snapshot --repo REPO --state PRIVATE_STATE --peer b.example
python3 endpoint/controller.py apply --repo REPO --state PRIVATE_STATE --peer b.example
python3 endpoint/controller.py confirm --repo REPO --state PRIVATE_STATE --peer b.example
```

Snapshot all referring hosts before the first apply. Immediately before each
apply, issue `pending/apply-approved` on that host only after fresh destination
reachability/return-path proof. Canary one host, test fresh bidirectional traffic,
handshake/counters, overlay v4/v6 and required ingress/storage/cluster health,
then serially apply/confirm remaining referring hosts. Issue `accept-approved`
only after that host's required external acceptance; `confirm` validates saved
and running state but **keeps the rollback armed**. Do not call host `release`
manually: that is an internal controller operation.

After all referring hosts accept, `controller.py commit --repo … --state …`
records the commit decision, atomically promotes the source candidate, releases
hosts serially, verifies every acknowledgment, then removes the durable marker.
The same advisory flock covers the entire ordinary generator command (including
install/clean) and each controller command; a persistent `.endpoint-pending`
marker blocks ordinary generation across controller exit/reboot. Never delete
that marker manually, generate from another checkout, or run another writer of
these source/config files while a transaction is pending.

On failure use `controller.py rollback --repo … --state …`. On controller
interruption use `controller.py reconcile --repo … --state …`; it resumes a
recorded commit, or rolls back all peers and source if any host already restored.
A pending transaction without a decision requires explicit rollback or commit.
If a host is unreachable, the lock stays: its local timer/boot hook restores it,
and the controller must later obtain every acknowledgment before unblocking
generation. Source remains journaled/locked while unreachable; there is no claim
that a disconnected controller can change its own disk. Partial release is
reversible: explicit controller rollback also restores released peers. Accepted
old/new destination addresses must remain available throughout reconciliation.

Rollback patches only the selected endpoint into the **current** saved file,
preserving unrelated edits, and restores the captured actual running endpoint
(which may have roamed away from the saved value). It never replays a stale
whole tunnel. Drift of that selected saved endpoint outside old/new fails closed
with journal retained. Unknown source drift also retains the lock for manual
review. Boot always restores an unconfirmed saved endpoint regardless of wall
clock, then runtime after wg0 startup. A fully released peer survives boot with
the new endpoint. Completed journals stay private as recovery evidence; archive
all referring journals and provision a new scope only after controller completion.

After endpoint acceptance, later tasks must still test controlled cold starts,
port1 transport, old-address retirement and config reapply. Never withdraw old
addresses from these prepared-tool/unit results alone.

## Checks actually available locally

```sh
python3 -m unittest discover -s endpoint -p 'test_*.py' -v
ruby -c wireguardmeshgenerator.rb
sh -n endpoint/freebsd/rc-rollback
sh -n endpoint/freebsd/rc-runtime
systemd-analyze verify endpoint/linux/*.service endpoint/linux/*.timer
```

Fixtures use generic names and synthetic public/private values, temporary
configs, native Ruby YAML parsing and `wg-quick strip` without creating/changing
an interface. They model command failures, exact learned-endpoint restoration,
clock expiry, boot ordering actions, partial controller release and reconciliation.
They do **not** prove OS-owned disconnected execution or actual reboot/service/
traffic behavior. Systemd verification on the controller reports the helper
executable absent because it is deliberately not installed there.
