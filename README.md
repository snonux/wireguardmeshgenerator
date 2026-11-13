# WireGuard Mesh Generator

## Installation

On Fedora Linux:

```sh
sudo dnf install wireguard-tools
bundler install
```

## Configuration

Have a look at the `wireguardmeshgenerator.yaml`

## Usage

* `rake generate`: Generate the WireGuard configuration files
* `rake install`: Install the generated configuration files to the remote machines
* `rake clean`: Clean up generated files

Android hosts with `android_gateways` generate one full-tunnel configuration per
listed gateway. The mapping values set Android-compatible tunnel names (15
characters maximum). For example, Pixel configs are written as
`p7p-blowfish.conf` and `p7p-fishfinger.conf`; import both into the WireGuard app
and select the available gateway manually. Every variant reuses the host keypair
generated under `keys/<host>/`; do not generate a separate key in the Android app.

## Access networks (wg2)

`access_networks:` in the YAML holds hub-and-spoke VPNs that are not part of
the wg0 mesh. `wg2` is the admin VPN terminated on the triggerfish router
(`10.99.0.0/24`, UDP 51822). `rake generate` renders:

* `dist/triggerfish/etc/hostname.wg2` (OpenBSD hub, `hostname.if(5)` format)
* `dist/earth/etc/wireguard/wg2.conf` (Linux client, run by `wg-quick@wg2`)

The keys under `keys/wg2/<host>/` were imported from the live router and
laptop; the generator never creates or rotates them and fails if one is
missing. The phone peer (`10.99.0.3`) is public-only: its private key exists
only on the phone, so no phone config is generated. There are no PSKs.

`rake install` does not install wg2. The router file is changed only through
conf's guarded `router-rollback` path; the generated file must stay identical to
the live `/etc/hostname.wg2` (compare `sha256` hashes, never print it). On
earth, back up `/etc/wireguard/wg2.conf`, copy the generated file there (root,
0600) and `systemctl restart wg-quick@wg2`.

`rake clean` deletes `keys/` including `keys/wg2/`. Don't run it; if the keys
are ever lost, re-import them from the router and earth, never regenerate.

## Details

Read this log post: https://foo.zone/gemfeed/2025-05-11-f3s-kubernetes-with-freebsd-part-5.html

## Scoped endpoint migration

The dormant [endpoint migration tools](endpoint/README.md) prepare single-referring-host
Endpoint updates with independent rollback and a durable generator/source journal.
They require separately accepted dual addresses and later native recovery/traffic
proofs; no endpoint migration is activated by normal generation.
