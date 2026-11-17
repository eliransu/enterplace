# Enterplace Enterprise

The enterprise features of Enterplace, under the Enterplace Commercial License (`LICENSE` here). A member of the repository's
Cargo workspace; it uses the open source crates as path dependencies and plugs into them through their extension hooks
(`docs/porting.md`). Its binary ships in the image as `/enterplace`.

## License keys (internals)

The customer-facing page is `docs/src/content/docs/operations/license.mdx` at the repository root. Code: `src/license.rs`.

- Token: `base64url(JSON payload) . base64url(Ed25519 signature over the payload bytes)`, no padding, one line. Payload: `customer`, `id`, `features` (names, or `all`), `seats`, `issued`, `expires` (UTC `YYYY-MM-DD`).
- The public key is the constant `PUBLIC_KEY` in `src/license.rs`. The private key is kept outside this repository (mode 600) and is never committed. Rotating it invalidates every license issued, so it is never overwritten by `license keygen`.
- States: valid before `expires`; grace for 30 days from `expires`; lapsed after. Lapsed turns enterprise features off; model traffic is never stopped. A set token that fails its check stops the start.
- Features check `license::unlocked("scim")`, or `license::current().require("scim")`, which returns code `license_required` with a message naming the fix.
- Seats are distinct key names in the keys file; over the limit is a start warning only.
- Issuing (staff only, needs `--features issuer`):

  ```sh
  cargo run -p enterplace-enterprise --features issuer -- license issue --signing-key <path to LICENSE_SIGNING_KEY> \
    --customer "Acme" --id lic_001 --features scim,siem --seats 50 --issued 2026-11-13 --expires 2027-11-13
  ```
