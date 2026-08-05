# Registration emulation and CDN hardening (v0.5.2)

## Registration emulation

Kerio Control registers against the mirror locally, without contacting
`register.kerio.com`. Emulation is enabled by default.

| Variable | Default | Description |
|---|---:|---|
| `KERIO_REGISTRATION_EMULATION` | `true` | Emulate the registration protocol instead of proxying to the official service |
| `KERIO_REGISTRATION_PROXY` | `true` | Transparent pass-through to the official endpoint (only when emulation is disabled) |
| `KERIO_REGISTRATION_FORCE_UNLIMITED` | `true` | Return `users: UNLIMITED` in `lookup`/`readinfo` responses |

Supported commands:

- `connect` — serves a cached captcha (`mirror/registration/security_image`) or
  downloads it from `register.kerio.com` (multipart form, `Kerio License
  Downloader (LicenseManager)` User-Agent). If the captcha is unavailable, an
  empty response with `X-Kerio-Reply-Code: 500` is returned (status 200).
- `lookup` — license data (`type: Server`, `total_users: UNLIMITED`,
  `reg_type: TRIAL`, expiry = now + 30 days).
- `readinfo` — registration profile with `addon_list[]`.
- `stored` — echoes the `base_id`.

Every emulated response sets `X-Kerio-Token`, `X-Kerio-Reply-Code: 200` and
`X-Kerio-Reply-Message`; bodies use `application/x-kerio-registration`.

## License validation (Kerio CDN)

`discoverKerioCDN` now distinguishes failures:

- Network/HTTP errors -> detailed log, `502 Bad Gateway` (retries already applied
  by the upstream client).
- `Invalid product license` / `Maintenance expired` -> the license is cleared
  (`Config.ClearLicenseNumber`, thread-safe), a Telegram notification is sent
  (if `TELEGRAM_NOTIFY_ON_ERROR`), `502 Bad Gateway`.

`Config` exposes `GetLicenseNumber`/`SetLicenseNumber`/`ClearLicenseNumber`
guarded by a mutex; all license readers were migrated to the accessor.

## Shield Matrix cache purge

`mirror.CheckAndPurgeShieldMatrixCache(conn, cfg, logger)` is invoked from the
canonical file handler. It compares the upstream `.../version` with the version
stored in the database; on change it removes `mirror/matrix/ipv4` and
`mirror/matrix/ipv6` and updates the DB version. Checked at most once per
`shieldMatrixCheckTTL` (5 minutes).

## Antivirus `versions.dat.gz`

The compressed `versions.dat.gz` is intentionally served as `404` so the Kerio
client falls back to the uncompressed `versions.dat`, which the mirror patches
for the Linux engine. The Bitdefender signature of `versions.sig` therefore
remains untouched.

## Web Filter forced key

| Variable | Default | Description |
|---|---:|---|
| `KERIO_WEBFILTER_FORCED_KEY` | empty | Force a Web Filter key instead of fetching it from `wf-activation.kerio.com` |

When set, `UpdateWebFilterKey` stores the forced key into the database and the
`/getkey.php` handler returns it without any upstream request.
