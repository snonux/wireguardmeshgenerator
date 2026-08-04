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

## Details

Read this log post: https://foo.zone/gemfeed/2025-05-11-f3s-kubernetes-with-freebsd-part-5.html
