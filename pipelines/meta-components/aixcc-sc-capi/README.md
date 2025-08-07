# Competition API

## Submission Restrictions / Limitations

For both the VDS and GP submissions, the data is evaluated against size and
content limits prior to any scoring evaluation. The following apply to all
submissions regardless of the Challenge Project:

* Per VDS submission, the `pov.data` field (PoV data blob) must be base64
  encoded and the original (plaintext) data must be no larger than 2 megabytes.
* Per GP submission, the `data` field (patch content) must be base64 encoded
  and the original (plaintext) data must be no larger than 100 kilobytes.
* Per GP submission, the decoded patch file must only modify files with the
  file extensions: ".c", ".h", ".in", and ".java".

## Running the e2e test

```bash
cp env.example env
# Edit env to include your github username and classic PAT with perms to read repos and pull packages
make e2e
```
