<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Test VMs

This prototype uses Nix, QEMU, and Ansible to boot and configure disposable Linux VMs for testing OpenShell packages and binaries. It supports HVF on Apple Silicon macOS, KVM on native-architecture Linux hosts, and a slower TCG fallback on Linux when KVM is unavailable.

## Requirements

- Nix with flakes enabled.
- Apple Silicon macOS with HVF, or a native-architecture Linux host. Linux uses KVM when `/dev/kvm` is available and falls back to QEMU TCG otherwise.
- Enough local capacity for a four-vCPU, 4 GiB guest and a disposable disk overlay.
- Native-architecture artifacts. TCG emulates the guest CPU on Linux but does not enable cross-architecture guests.

The first run downloads the selected cloud image and VM runtime. Nix reuses those immutable inputs on later runs, while each guest starts from a fresh writable overlay.

## Directory structure

```text
nix/vm/
├── README.md
├── default.nix
├── run.sh
├── distros/
│   ├── ubuntu.nix
│   ├── centos.nix
│   ├── fedora.nix
│   └── rocky.nix
└── configuration/
    ├── docker.yml
    ├── podman.yml
    └── selinux.yml
```

- `default.nix` assembles the VM flake app. It selects host architecture and acceleration, supplies QEMU and Ansible through the Nix runtime closure, and exposes distro profiles and configuration playbooks as Nix-store catalogs.
- `run.sh` owns the disposable VM lifecycle: argument validation, cloud-image realization, cloud-init seed creation, QEMU startup, SSH readiness, Ansible execution, artifact installation, guest command execution, and cleanup.
- `distros/*.nix` define the immutable base-image catalog. Each record pins the image URL and hash and declares the expected OS ID, version, and package family. Distro definitions do not provision extra software.
- `configuration/*.yml` are host-executed Ansible playbooks that layer optional capabilities onto a base guest. Configurations remain independent and run in the order supplied with repeated `--with` arguments.
- `README.md` documents the supported combinations and developer interface.

The root [`flake.nix`](../../flake.nix) exposes this directory as the `test-vm` app. Debian artifact creation remains outside the VM harness in [`tasks/scripts/package-deb.sh`](../../tasks/scripts/package-deb.sh); the runner only installs or copies artifacts that already exist.

## Supported configurations

| Distro | Docker | Podman | SELinux | Package format |
| --- | --- | --- | --- | --- |
| Ubuntu 24.04 | Yes | Yes | No | `.deb` |
| CentOS Stream 10 | No | Yes | Yes | `.rpm` |
| Fedora 44 | No | Yes | Yes | `.rpm` |
| Rocky Linux 9 | Yes | Yes | Yes | `.rpm` |

List the available distros and configurations:

```shell
nix run .#test-vm -- --list
```

## Run a host or test-VM E2E suite

[`e2e/run.sh`](../../e2e/run.sh) builds OpenShell from the current checkout, starts a gateway from a supplied TOML file, and runs one named host-side suite against it. This opt-in path is separate from `mise run e2e:vm`: `e2e/run.sh` selects where the gateway process runs, while the supplied gateway config selects the compute driver. It is not part of the default E2E task or CI graph.

Omit both `--vm` and `--with` to run the gateway on the host:

```shell
e2e/run.sh \
  --gateway-config e2e/configs/gateway/docker.toml \
  --suite smoke
```

Pass `--vm` or at least one `--with` to run the gateway in a disposable test VM:

```shell
e2e/run.sh \
  --vm ubuntu \
  --with docker \
  --gateway-config e2e/configs/gateway/docker.toml \
  --suite smoke
```

Use `--guest-setup` when a driver needs checkout-specific guest preparation
before the gateway starts. For example, the Podman shutdown suite builds a
supervisor image around the staged `openshell-sandbox` binary:

```shell
e2e/run.sh \
  --vm ubuntu \
  --with podman \
  --guest-setup e2e/guest-setup/podman-supervisor.sh \
  --gateway-config e2e/configs/gateway/podman.toml \
  --suite podman-shutdown
```

Set `OPENSHELL_E2E_EXPECT_SHUTDOWN_CLOSES=1` when a stacked change must
classify supervisor and relay transport closures as expected teardown events.

Supplying `--with` without `--vm` selects Ubuntu. `--with` is repeatable and configurations run in input order. Supplying `--vm` without `--with` boots the selected base image without adding software. The wrapper validates both values against the test-VM catalogs:

```shell
e2e/run.sh \
  --vm rocky \
  --with docker \
  --with selinux \
  --gateway-config e2e/configs/gateway/docker.toml \
  --suite smoke
```

The equivalent passthrough task accepts the same arguments:

```shell
mise run e2e:run -- \
  --with docker \
  --gateway-config e2e/configs/gateway/docker.toml \
  --suite smoke
```

The wrapper always builds the tested binaries; it does not accept packages or use release artifacts. Both modes build a native host `openshell` CLI and a static Linux `openshell-sandbox` for the host architecture. Host mode also builds a native `openshell-gateway` with bundled Z3. VM mode builds a static Linux `openshell` and a Linux GNU `openshell-gateway` with bundled Z3 and a glibc 2.28 floor, then stages all three guest binaries through the VM runner's `--copy` interface.

The Linux targets match the host and guest architecture:

| Host architecture | CLI and sandbox | Gateway |
| --- | --- | --- |
| x86_64 | `x86_64-unknown-linux-musl` | `x86_64-unknown-linux-gnu.2.28` |
| aarch64 | `aarch64-unknown-linux-musl` | `aarch64-unknown-linux-gnu.2.28` |

These cross-builds use the Zig and `cargo-zigbuild` versions pinned in [`mise.toml`](../../mise.toml). Install the repository's mise tools before running the wrapper. The wrapper also requires Python 3 and OpenSSL; VM mode requires `base64`. Cargo stores outputs in its normal target directory, so later runs reuse current artifacts. VM mode additionally requires the Nix, QEMU, and host-capacity prerequisites above; host mode does not invoke Nix, QEMU, or Ansible.

Gateway configs are ordinary, fully resolved TOML files under `e2e/configs/gateway/`. The wrapper does not inspect or rewrite them. It supplies only the bind address, gateway port, plaintext transport, and isolated XDG directories at launch. Use portable relative paths for host files. The initial Docker config points `supervisor_bin` at `.cache/openshell-e2e/bin/openshell-sandbox`; the wrapper stages that path under the repository in host mode and under `/home/openshell` in VM mode. It also generates and stages the local sandbox JWT material referenced by the initial config.

Suites are executable scripts under `e2e/suites/` and use lowercase letters, digits, and hyphens for their names. The wrapper exports the selected endpoint, isolated gateway registration, native host CLI path, mode metadata, source config path, and forwarded ports before executing a suite. Add new configs and suites without adding scenario branches to `e2e/run.sh`.

Set `OPENSHELL_E2E_KEEP=1` to retain wrapper state after a host-mode run. In VM mode the wrapper also passes `--keep` to the test-VM runner so its overlay and logs remain available.

## Open an interactive VM

Boot a base Ubuntu VM:

```shell
nix run .#test-vm -- --distro ubuntu
```

Apply the Docker configuration before opening the SSH session:

```shell
nix run .#test-vm -- --distro ubuntu --with docker
```

Other combinations use the same interface:

```shell
nix run .#test-vm -- --distro rocky --with docker
nix run .#test-vm -- --distro centos --with podman
nix run .#test-vm -- --distro fedora --with podman
```

Configurations are repeatable:

```shell
nix run .#test-vm -- \
  --distro ubuntu \
  --with docker \
  --with podman
```

Ensure SELinux is enforcing on CentOS, Fedora, or Rocky:

```shell
nix run .#test-vm -- \
  --distro rocky \
  --with docker \
  --with selinux \
  -- getenforce
```

`--with selinux` installs the required tooling, persists `SELINUX=enforcing`, applies enforcing mode live, and verifies the result. It fails on Ubuntu and on guests where SELinux is fully disabled and would require a reboot to enable.

## Ansible configurations

Configurations are Ansible playbooks stored under `nix/vm/configuration/`. Ansible runs on the host using the VM's ephemeral SSH key and loopback port. The guest does not install Ansible.

Configurations run in the order provided on the command line. OpenShell packages and copied binaries are installed after all configurations succeed.

## Install an OpenShell package

Package existing ARM64 Linux binaries with the repository's `package:deb:arm64` mise task:

```shell
OPENSHELL_CLI_BINARY="$PWD/target/aarch64-unknown-linux-musl/release/openshell" \
OPENSHELL_GATEWAY_BINARY="$PWD/target/aarch64-unknown-linux-gnu/release/openshell-gateway" \
OPENSHELL_DRIVER_VM_BINARY="$PWD/target/aarch64-unknown-linux-gnu/release/openshell-driver-vm" \
OPENSHELL_DEB_VERSION=0.0.0-local \
OPENSHELL_OUTPUT_DIR="$PWD/artifacts" \
nix develop --command mise run package:deb:arm64
```

Install the package in an Ubuntu VM and run a command:

```shell
nix run .#test-vm -- \
  --distro ubuntu \
  --with docker \
  --install artifacts/openshell_0.0.0-local_arm64.deb \
  -- openshell --version
```

For an x86_64 Linux guest, supply x86_64 binaries and use `package:deb:amd64`. The package architecture must match the host and guest architecture.

`--install` is repeatable. Debian packages are accepted by Ubuntu; RPM packages are accepted by CentOS, Fedora, and Rocky Linux. This prototype can install an existing RPM but does not build one.

## Copy binaries directly

Use `--copy SOURCE:DEST` to install an executable without creating a package:

```shell
nix run .#test-vm -- \
  --distro ubuntu \
  --copy ./openshell:/usr/local/bin/openshell \
  -- openshell --version
```

The destination must be an absolute guest path. Copied files are installed with mode `0755`.

## Runner options

```text
--distro NAME       Base distro: ubuntu, centos, fedora, or rocky
--with NAME         Apply docker, podman, or selinux; repeatable
--install PATH      Install a .deb or .rpm package; repeatable
--copy SRC:DEST     Copy an executable into the guest; repeatable
--ssh-port PORT     Use a specific loopback SSH forwarding port
--forward-port HOST_PORT:GUEST_PORT
                    Forward a loopback host port to a guest port; repeatable
--keep              Preserve the disk overlay and logs after shutdown
--list              List distros and configurations
```

Each `--forward-port` binds only `127.0.0.1` on the host. Both ports must be unprivileged values from 1024 through 65535, and each host port may appear only once.

Arguments after `--` are executed inside the guest. Without a command, the runner opens an interactive SSH session.

## Lifecycle

Nix downloads and caches the selected, hash-pinned cloud image. Each invocation then:

1. Creates a temporary QCOW2 overlay.
2. Boots QEMU with HVF, KVM, or the Linux TCG fallback.
3. Creates an ephemeral `openshell` user and SSH key through cloud-init.
4. Applies the selected Ansible configurations.
5. Installs or copies the supplied artifacts.
6. Opens SSH or executes the requested guest command.
7. Powers off QEMU and deletes the overlay.

Use `--keep` to preserve the overlay, cloud-init seed, SSH key, and serial log for debugging. The retained directory is printed when the runner exits.

## Current limitations

- Host and guest architectures must match.
- TCG is slower than hardware virtualization and uses a longer SSH readiness timeout.
- Configurations are applied fresh on every run; prepared VM caching is not implemented.
- Guest ports are reachable from the host only when explicitly exposed with loopback-only `--forward-port`.
- The low-level VM runner does not build OpenShell, configure a gateway, or select an E2E test suite. Use `e2e/run.sh` for that orchestration.
