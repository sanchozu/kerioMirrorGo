# Kerio legacy antivirus client compatibility (v0.5.8)

Some Kerio Control 10.x clients require a successful `versions.dat.gz` response
and do not retry after a 404. The mirror now gzip-wraps the original signed
`versions.dat` bytes without modifying their contents.

The same clients request legacy paths such as
`av64bit_<id>/avx/Plugins/7zip.xmd.gzip`. Kerio's CDN stores those files under
the content-addressed `/v2/repository/` paths listed in the signed
`versions3.dat`; the mirror resolves the legacy path through that manifest and
serves the exact CDN object. Engine archives still pass through the ELF/PE
safety check before entering the cache.
