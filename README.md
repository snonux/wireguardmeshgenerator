# WireGuard Mesh Generator

This generates the WireGuard config for my f3s project. This script is run on my Fedora Linux laptop.

## Installation

```sh
bundler install
sudo dnf install -y wireguard-tools
```

## Generate

```sh
rake generate
```

It will generate the configs and scp the configs to the hosts

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

```sh
paul@f0:~ % doas freebsd-update fetch..... and so on... reboot
paul@f0:~ % doas pkg update
paul@f0:~ % doas pkg upgrade
paul@f0:~ % reboot

paul@f0:~ % doas pkg install wireguard-tools
paul@f0:~ % doas sysrc wireguard_interfaces=wg0
wireguard_interfaces:  -> wg0
paul@f0:~ % doas sysrc wireguard_enable=YES
wireguard_enable:  -> YES
paul@f0:~ % doas mkdir -p /usr/local/etc/wireguard
paul@f0:~ % doas touch /usr/local/etc/wireguard/wg0.conf
paul@f0:~ % doas service wireguard start
```

### Rocky Linux 9

```sh
[root@r0 ~] dnf update -y
[root@r0 ~] reboot

[root@r0 ~] dnf install wireguard-tools
[root@r0 ~] mkdir -p /etc/wireguard
[root@r0 ~] touch /etc/wireguard/wg0.conf
[root@r0 ~] systemctl enable wg-quick@wg0.service
[root@r0 ~] systemctl start wg-quick@wg0.service
```

### Install the config

```sh
rake install
```


