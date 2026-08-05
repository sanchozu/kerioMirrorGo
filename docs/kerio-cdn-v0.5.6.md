# Kerio CDN routing (v0.5.7)

Antivirus files are now cached on demand from the licensed Kerio CDN. The
mirror preserves the exact request path, including `/v2/repository/...`, and
uses the CDN host, `WSLib 1.4 [3, 0, 0, 94]`, and `Accept: */*` headers.

The legacy `versions.dat.gz` request returns `404` so Kerio Control falls back
to the signed `versions.dat`. The mirror never regenerates the gzip wrapper or
patches the signed metadata. Scheduled Bitdefender downloads from the public
Bitdefender CDN are disabled in mirror mode; files are fetched only after a
licensed `THDdir` has been discovered.
