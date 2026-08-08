# crsys.dev — the project site

This folder is served by GitHub Pages (source: `main` / `docs`). It is a single
self-contained `index.html`: no build step, no dependencies, no external fonts
or scripts — the same no-dependency stance as the library.

The one interactive piece decodes a real container from `tests/vectors.json`
(public data), byte by byte. It reimplements no cryptography.

To use a custom domain later, add a `CNAME` file here containing the domain and
set the DNS records at the registrar.
