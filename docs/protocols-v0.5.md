# Kerio protocol endpoints (v0.5.0)

## Canonical API

- `GET /api/kerio/updates/ids/link`
- `GET /api/kerio/updates/ids/files/:name`
- `GET /api/kerio/updates/geoip/link`
- `GET /api/kerio/updates/geoip/files/:name`
- `GET /api/kerio/updates/antivirus/link`
- `GET /api/kerio/updates/antivirus/files/*`
- `GET /api/kerio/updates/antispam/files/*`
- `GET /api/kerio/updates/shieldmatrix/link`
- `GET /api/kerio/updates/shieldmatrix/files/version`
- `GET /api/kerio/updates/shieldmatrix/files/*`
- `GET /api/kerio/updates/webfilter/key`
- `POST /api/kerio/updates/distro/check`
- `GET /api/kerio/updates/distro/files/:name`
- `HEAD|POST /api/kerio/updates/registration`

Requests sent to original Kerio hostnames are rewritten to these routes by the Echo pre-router. Existing legacy routes such as `/update.php`, `/getkey.php`, `/check_update/`, `/control-update/*`, and `/matrix/*` remain available.

## Environment variables

| Variable | Default | Description |
|---|---:|---|
| `KERIO_PUBLIC_BASE_URL` | request host | Explicit base URL returned to Kerio clients |
| `KERIO_ANTIVIRUS_UPSTREAM` | `BITDEFENDER_PROXY_BASE_URL` | Antivirus upstream; use `https://bdupdate.kerio.com` for Kerio CDN discovery |
| `KERIO_ANTISPAM_UPSTREAM` | `https://upgrade.bitdefender.com` | Separate antispam upstream |
| `KERIO_ANTIVIRUS_DIRECT` | `false` | Return upstream `THDdir` instead of the local mirror URL |
| `KERIO_METADATA_TTL_SECONDS` | `300` | TTL for `versions.id`; expiration invalidates sibling `versions.*` files |
| `KERIO_DISTRO_ENABLED` | `false` | Enable local Kerio Control distro checks |
| `KERIO_DISTRO_FILE` | empty | Official `.img` file stored in `mirror/distros/` |
| `KERIO_DISTRO_VERSION` | empty | Version represented by the selected image, e.g. `9.5.0-9017` |
| `KERIO_REGISTRATION_PROXY` | `true` | Transparent pass-through to the official registration endpoint |

## Security model

- Distro images are never generated or signed by the mirror. Only pre-existing `.img` and `.sig` files under `mirror/distros/` are served.
- Registration responses are not emulated or modified; the endpoint proxies the official service.
- File paths are constrained with `filepath.Rel` and strict filename validation.
- Cache files are published through temporary files and atomic rename.
