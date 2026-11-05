# Bounded endpoint recovery trials (conf z24)

Prepared offline; **no native proof or installation is claimed**. Root review
and serial coordination precede installation, timer activation, authorizations,
endpoint changes and any reboot. Do not run during guest/parent address trials,
power work, or unattended upgrade/reboot activity. Inspect actual schedules and
pending state first: last recorded f3 :15, r2 :45 and standalone Rocky :55.

## Trial protocol

Use the same host configuration and fixed journal paths as production, with an
additional `"protocol": "canary"` field and a fresh unique `id` for each trial.
Default/explicit `production` retains the existing production contract.
Canary snapshots require installed, active native watchdog/boot hooks, but use
`pending/canary-approved.json` instead of `recovery-approved`. The root-owned
0600 authorization is **permission to test**, never an assertion that recovery
has passed. It has exactly these fields:

```json
{"config_sha256": "SHA256_OF_SORTED_JSON_CONFIG", "confirm_before": 1800000120, "expires": 1800000240}
```

Compute `config_sha256` privately with Python's
`hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()`.
The two timestamps are absolute host epoch seconds: now < confirm_before <
expires <= now+900. Choose an inner 120-second deadline and an outer 240-second
lease, allowing for FreeBSD's one-minute cron cadence and operation latency.
Snapshot records both deadlines; apply rechecks exact authorization, readiness
and the existing fresh `apply-approved` ID gate. An expired/replaced gate, a
foreign config, reused journal or drift fails closed. Do not extend a live lease.

Unconfirmed trials restore at the inner deadline. To exercise confirmation,
write only `canary-confirm-approved` containing the trial ID after required
external checks; `confirm` runs the real saved/runtime acceptance comparisons
and marks the canary confirmed. NEW then survives watchdog ticks beyond the
inner deadline. **The outer lease still restores confirmed canaries**, even
after controller loss. Boot restores every canary's saved endpoint before wg0,
then its captured running endpoint afterwards, regardless of confirmation or
clock. The `release` action always refuses canaries. A failed restore retains
the journal for the native watchdog's retry.

The same host flock serializes snapshot/apply/confirm/watchdog/restore, including
confirmation racing expiry. A confirmation that loses to restoration refuses.
Ordinary production `confirm` still validates without disarming; production
controller `release` remains conditional on complete-referrer acceptance/source
promotion. Canary scope receipts are deliberately incompatible with production
receipts; the controller refuses a canary manifest before creating a marker,
and refuses a canary host before a production mutation or source promotion.

The canary protocol never writes generator YAML or creates a source candidate.
Serialize all generator, config installer and endpoint writers out of the entire
trial and journal archive window. No production controller transaction may be
pending. Keep authoritative YAML OLD and privately compare its digest before
and after. Do not run mesh install, generate, clean, whole-tunnel reload or
restore, or edit any key. Both old/new destination addresses remain accepted.

## Exact native scope and prerequisites

| Referring host | Destination peer | Saved endpoint delta | Host interpreter/journal |
|---|---|---|---|
| r2 | f3 actual existing wg0 identity | 192.168.1.133:56709 → 10.20.0.133:56709 | /usr/bin/python3; /var/lib/gonf-endpoint/pending |
| f3 | r2 actual existing wg0 identity | 192.168.1.122:56709 → 10.20.0.122:56709 | /usr/local/bin/python3.12; /var/db/gonf-endpoint/pending |

Use literal management SSH port 22, with the already approved sudo/doas prefix
appropriate to each host. Resolve identity privately by matching saved and live
configuration and generator public identity, never by inventing a key. Do not
use the standalone FreeBSD guest with known identity drift as a canary.
Capture the exact current source SHA256 in the scope; do not print configurations.

Both destinations already have accepted dual Stage: f3 old .1.133/new .20.133,
r2 old .1.122/new .20.122, with local ULA ::133/::122. Reverify fresh authenticated
access to both literal addresses, source/return routes (including laptop
192.168.99.2/32 via 192.168.1.2), native UDP56709 policy and unchanged defaults
via 192.168.1.1 before authorizing either direction. Review f3's separately
prepared fail-closed UDP source-guard policy before testing r2→f3.

Provision only the reviewed helper, fixed config, private directories, OS-owned
timer/cron and boot hooks listed in README. The FreeBSD source choice is
`python312`'s real `/usr/local/bin/python3.12`, already observed as 3.12.15 on f3;
verify `/usr/sbin/pkg which /usr/local/bin/python3.12` and executable version
afresh. A missing package belongs in the scoped gonf package plan as
`Package("python312")`, reviewed before deployment. Do not create a handwritten
symlink or rely on an interactive PATH. No package deployment was performed by
this preparation. Linux must similarly verify /usr/bin/python3 >=3.9.
Review actual startup ordering, dependencies, cron/timer health and SELinux;
the tool's readiness checks are necessary, not native execution proof.

## Serial commands and acceptance

For each direction, use `H` = the table's exact interpreter plus
`/usr/local/sbin/gonf-endpoint-rollback`, and `J` = its exact journal path.
Run each command through the existing noninteractive root prefix. These are
host actions, **not** `controller.py` actions:

```text
H scope J
H snapshot J
H apply J
H status J
H confirm J             # confirmation trial only, after canary-confirm-approved
H restore-runtime J     # explicit cleanup or failure; safe to repeat
```

1. Inspect pending native address/endpoint journals, scheduler timing and host
   health, and take private saved/runtime snapshots. Start with r2→f3. Install
   dormant artifacts, inspect their exact bytes, then activate OS-owned hooks
   during the reviewed window. Prepare a fresh private config/authorization and
   fresh `apply-approved` after management/return-path/UDP proof. Do not create
   `recovery-approved` or `accept-approved` for a canary.
2. Expiry trial: snapshot/apply; validate only the selected endpoint changed,
   establish fresh bidirectional traffic and counters, then disconnect trial
   SSH sessions and let native expiry run without controller commands. Reconnect
   through old management after inner deadline plus scheduler cadence; verify
   `restored`, exact saved OLD and captured actual runtime endpoint, unchanged
   keys/peers/AllowedIPs/keepalive/public endpoints/overlay v4/v6/wg1, and services.
   Repeat explicit restore to prove idempotence. Archive the entire journal
   privately only after successful restoration; never delete pending evidence.
3. Confirmation trial with new ID/config/authorization: snapshot/apply; repeat
   fresh acceptance, provision only canary-confirm-approved and confirm. Wait
   past the inner deadline plus scheduler cadence; independently observe NEW in
   saved/live state and successful traffic. Do not claim this from immediate
   command success. Explicitly restore before outer expiry, or deliberately
   disconnect and verify automatic outer expiry with fresh management afterwards.
   The latter also proves a confirmed trial cannot escape its outer lease.
4. Unconfirmed boot trial with another fresh scope: snapshot/apply, then perform
   the separately coordinated controlled host reboot while within the outer
   lease. Capture private native startup evidence that saved OLD was restored
   before wg0 loads and captured runtime OLD afterwards, with required services
   healthy. r2 reboot requires other etcd members healthy; f3 reboot additionally
   affects its guests and must be coordinated after all guest trials complete.
   No automatic reboot command is supplied. A fixture boot action is not proof.
5. Reapply the reviewed dormant helper/service/config plan with no pending trial;
   prove it does not recreate a journal, authorize a change, change the endpoint,
   or depend on a manually created interpreter symlink. Never use whole-mesh
   install as reapply. Repeat the complete sequence for f3→r2 only after r2→f3
   is restored/archived and the next window is checked. Record each native
   observation and failed/untested gate honestly.

Only after all required native expiry, confirmation, outer expiry, boot and
reapply checks actually pass may an operator issue production recovery approval
for a later unique production transaction. It remains a separate assertion.
These isolated canaries do not make the full f3 source migration eligible:
every persisted referrer f0–f2/r0–r2 must be routable, snapshot and accept before
authoritative f3 YAML promotion. Old-only peers currently route .20 via upstream
192.168.1.1. Never fake an r2-only complete production manifest. No addresses,
cabling, AP/SSID/controller IP, keys, peer sets or tunnel networks change here.
