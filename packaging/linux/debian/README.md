# Debian packaging

This directory will contain the files needed to build a `.deb` package for
VNC Remote Secure using `dpkg-deb` / `debhelper`.

## Planned contents

| File         | Purpose                                                       |
|--------------|---------------------------------------------------------------|
| `control`    | Package metadata (name, version, dependencies, description). |
| `postinst`   | Post-installation hook: create dirs, reload systemd, set perms. |
| `prerm`      | Pre-removal hook: stop services before uninstall.            |
| `postrm`     | Post-removal hook: purge config/data on `purge`.             |
| `rules`      | `debhelper` build rules.                                      |
| `changelog`  | Debian changelog (`dch` format).                              |
| `compat`     | Debhelper compatibility level.                               |
| `install`    | File mapping from build tree to install tree.                |
| `vnc-remote-secure.dirs` | Extra directories created by the package.      |

## Build (future)

```bash
# From the repository root, once the files above exist:
dpkg-buildpackage -us -uc -b
# Resulting .deb will appear in the parent directory.
```

## Status

All files above except `compat` exist (`debhelper-compat (= 13)` in
`control` replaces it). Build with `dpkg-buildpackage` on a Debian
system with `debhelper`, `pybuild-plugin-pyproject` and
`python3-all` installed. The `postinst` creates the `vnc-remote`
system user and state dirs; `vnc-remote install` completes the
OS-integration (firewall, certs, config.env).
