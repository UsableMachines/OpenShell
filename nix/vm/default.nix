# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# PROTOTYPE: Composable distro VMs for installing and exercising artifacts.

{
  pkgs,
  architecture ? if pkgs.stdenv.hostPlatform.isAarch64 then "aarch64" else "x86_64",
  accelerator ? null,
  useQemuFirmware ? false,
}:

let
  hostArchitecture = if pkgs.stdenv.hostPlatform.isAarch64 then "aarch64" else "x86_64";
  isAarch64 = architecture == "aarch64";
  isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
  guestMatchesHost = architecture == hostArchitecture;
  qemu = pkgs.qemu.override { hostCpuOnly = guestMatchesHost; };
  qemuBinary =
    if isAarch64 then "${qemu}/bin/qemu-system-aarch64" else "${qemu}/bin/qemu-system-x86_64";
  selectedAccelerator =
    if accelerator != null then
      accelerator
    else if isDarwin then
      if guestMatchesHost then "hvf" else "tcg"
    else if guestMatchesHost then
      "kvm"
    else
      "tcg";
  firmwareCode =
    if useQemuFirmware && isAarch64 then
      "${qemu}/share/qemu/edk2-aarch64-code.fd"
    else
      pkgs.OVMF.firmware;
  firmwareVars =
    if useQemuFirmware && isAarch64 then "${qemu}/share/qemu/edk2-arm-vars.fd" else pkgs.OVMF.variables;

  distros = {
    ubuntu = import ./distros/ubuntu.nix { inherit pkgs architecture; };
    centos = import ./distros/centos.nix { inherit pkgs architecture; };
    fedora = import ./distros/fedora.nix { inherit pkgs architecture; };
    rocky = import ./distros/rocky.nix { inherit pkgs architecture; };
  };

  configurations = {
    docker = ./configuration/docker.yml;
    podman = ./configuration/podman.yml;
    selinux = ./configuration/selinux.yml;
  };

  mkDistroProfile =
    name: distro:
    pkgs.writeText "openshell-test-vm-${name}" ''
      TEST_VM_IMAGE_DRV=${builtins.unsafeDiscardStringContext distro.image.drvPath}
      TEST_VM_OS_ID=${pkgs.lib.escapeShellArg distro.osId}
      TEST_VM_OS_VERSION=${pkgs.lib.escapeShellArg distro.osVersion}
      TEST_VM_PACKAGE_FAMILY=${pkgs.lib.escapeShellArg distro.packageFamily}
      export TEST_VM_IMAGE_DRV TEST_VM_OS_ID TEST_VM_OS_VERSION TEST_VM_PACKAGE_FAMILY
    '';

  distroCatalog = pkgs.linkFarm "openshell-test-vm-distros" (
    pkgs.lib.mapAttrsToList (name: distro: {
      inherit name;
      path = mkDistroProfile name distro;
    }) distros
  );

  configurationCatalog = pkgs.linkFarm "openshell-test-vm-configurations" (
    pkgs.lib.mapAttrsToList (name: path: { inherit name path; }) configurations
  );

  runner = pkgs.writeShellApplication {
    name = "openshell-test-vm";
    runtimeInputs = [
      qemu
      pkgs.python3Packages.ansible-core
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.nix
      pkgs.openssh
      pkgs.python3
      pkgs.xorriso
    ];
    text = ''
      export OPENSHELL_TEST_VM_RUNTIME=1
      export OPENSHELL_TEST_VM_DISTROS=${distroCatalog}
      export OPENSHELL_TEST_VM_CONFIGURATIONS=${configurationCatalog}
      export TEST_VM_QEMU=${qemuBinary}
      export TEST_VM_FIRMWARE_CODE=${firmwareCode}
      export TEST_VM_FIRMWARE_VARS=${firmwareVars}
      export TEST_VM_MACHINE=${if isAarch64 then "virt" else "q35"}
      export TEST_VM_ACCELERATOR=${selectedAccelerator}
      export TEST_VM_ARCHITECTURE=${architecture}
      exec ${pkgs.bash}/bin/bash ${./run.sh} "$@"
    '';
  };
in
{
  app = {
    type = "app";
    program = "${runner}/bin/openshell-test-vm";
    meta.description = "Boot and configure a disposable distro VM";
  };
}
