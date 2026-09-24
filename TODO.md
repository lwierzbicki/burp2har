# TODO — burp2har

## Ideas

- **Brotli / zstd bodies:** decode when the optional `brotli` / `zstandard`
  packages are installed (or `compression.zstd` on Python 3.14+), keeping the
  core dependency-free.

- **Multipart `postData.params`:** split `multipart/form-data` bodies into
  params (with `fileName` / `contentType` for file parts).

- **`Max-Age` on `Set-Cookie`:** convert to `expires` relative to the entry's
  start time.

- **Verify HTTP/2 export shape against real Burp exports:** pseudo-headers are
  handled, but it's unconfirmed whether Burp ever writes them rather than an
  HTTP/1-style request line.
