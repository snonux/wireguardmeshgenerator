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

## Details

Read this log post: https://foo.zone/gemfeed/2025-05-11-f3s-kubernetes-with-freebsd-part-5.html
