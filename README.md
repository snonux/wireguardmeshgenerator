# WireGuard Mesh Generator

This generates the WireGuard config for my f3s project. This script is run on my Fedora Linux laptop.

## Installation

```sh
bundler install
sudo dnf install -y wireguard-tools
```

## Usage

```sh
rake
```

Result:

```sh
❯ find keys
keys
keys/f0
keys/f0/privkey
keys/f0/pubkey
keys/f1
keys/f1/privkey
keys/f1/pubkey
keys/f2
keys/f2/privkey
keys/f2/pubkey
keys/r0
keys/r0/privkey
keys/r0/pubkey
keys/r1
keys/r1/privkey
keys/r1/pubkey
keys/r2
keys/r2/privkey
keys/r2/pubkey
```

## Installation

### FreeBSD

https://docs.vultr.com/how-to-install-wireguard-vpn-on-freebsd-14-0

```sh
doas freebsd-update fetch..... and so on
doas pkg install wireguard-tools

paul@f0:~ % doas sysrc wireguard_interfaces="wg0"
wireguard_interfaces:  -> wg0

paul@f0:~ % doas sysrc wireguard_enable="YES"
wireguard_enable:  -> YES

```


