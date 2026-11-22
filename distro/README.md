# Erebus OS — live-build distro config

Builds the Erebus live ISO: a lightweight Debian/Kali-based image with Erebus and a
curated tool set preinstalled. Two editions from one config, both arches.

> **Cannot be built in the cloud sandbox.** `live-build` needs a Debian/Ubuntu host,
> root, and plenty of disk. Run this on your own Linux box. The scripts here are a
> scaffold — review them before running, and treat the first builds as experiments.

## Prerequisites (Debian/Ubuntu host)
```bash
sudo apt update && sudo apt install -y live-build git
```

## Build
```bash
# amnesic Live edition, x86-64 (the clean-room stick)
sudo ./build.sh --edition live --arch amd64

# installed Workstation edition (reporting + vault + graph), x86-64
sudo ./build.sh --edition workstation --arch amd64

# Apple-Silicon / Pi image
sudo ./build.sh --edition live --arch arm64
```
The ISO lands at `./erebus-<edition>-<arch>.iso`.

## What the config does
- Starts from a **minimal** Debian base (not the Kali everything-bundle) and layers only
  the tools in `packages.list` + a tiling WM, to keep the image small (research doc §7).
- `--edition` selects the package set and the default log level, and gates reporting / vault
  / knowledge-graph on (workstation) or off (live) — matching `Framework(edition=...)`.
- `overlay/` is copied into the image (`includes.chroot`): an **authorized-use banner**, a
  placeholder for Erebus at `/opt/erebus`, and the selective-persistence example.
- Live edition is amnesic (`toram`); Workstation installs to disk. Persistence (§8) is an
  opt-in LUKS partition created by the loader, not baked into the ISO.

## Still to do (see the handoff / research doc §7–§8)
- Flesh out `includes.chroot` to actually install Erebus (`pip install` / a .deb) and the
  first-boot `erebus-tables` / `nuclei -update-templates` / `searchsploit -u` fetchers.
- The `erebus-flash` loader (write ISO + LUKS persistence + preserve-on-reflash) is **not**
  included here — it does destructive `dd`/partitioning and needs careful, real-hardware
  development. Build it deliberately, with device guards and a dry-run default.
