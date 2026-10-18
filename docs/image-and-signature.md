# Image and signature

## Sources

The image comes from a registry, or from a copy already on the machine for an install without network access. `--image` takes a registry reference or one of these:

- `oci:DIR` reads an OCI image layout, as `skopeo copy docker://IMAGE oci:DIR` writes it.
- `oci-archive:FILE` reads the same layout from a tar archive, in place. `skopeo copy docker://IMAGE oci-archive:FILE`, `podman save --format oci-archive` and `docker save` from Docker 25 on write it.

A reference after the path, as in skopeo's `oci:DIR:TAG`, is not supported: the whole value is taken as the path. A `docker save` archive from before Docker 25 has no OCI `index.json` and is refused. Convert it with `skopeo copy docker-archive:FILE oci-archive:FILE`. None of these copies the image's signature, see [Signatures in a layout](#signatures-in-a-layout).

## Checks

A local image is checked like a pulled one. Each of these refusals has class `bad-image`:

- The manifest, the config and every layer must match the digests the index names. Otherwise the install stops before that layer is applied. A manifest, config or layer that an index or manifest names by a sha512 digest is refused too.
- The host's architecture is picked from a multi-architecture index, and the image's config must name it too. So an image for another architecture is refused before any layer is downloaded.
- A layout holding more than one image for the host's architecture is refused rather than guessed. So is a layout with an image that cannot be read, if that image is for the host's architecture or names no platform. Copy the image you want into a layout of its own.
- The index, manifests, config and the signature's referrers and bundles must be strict JSON. An object that names a member twice, invalid UTF-8 or data after the value is refused even when the digest matches, since two parsers may read it differently. A signature referrer the registry serves as an index is refused too. A legacy `.sig` signature is not checked this way: cosign parses it on its own.

## Downloads

Each layer is downloaded whole, checked, and then unpacked. A download is retried when it breaks off, receives nothing for a minute, gets a 5xx, 408 or 429 answer, or does not match its digest. There are five attempts in all, 1, 2, 4 and 8 seconds apart. Any other answer, such as not found or unauthorized, stops the install at once. So does a certificate the machine does not accept. A pull-through cache must start sending a layer within that minute, or the attempt counts as stalled.

Plain http is used only for a registry at a loopback address such as `127.0.0.1:5000`. `localhost` does not count, as it is a name that DNS may resolve elsewhere. Where the registry client would fall back to http, for a private address or a `.local` name, it asks over https instead. The same goes for a token URL on http. A redirect to plain http is refused with `bad-image`, including one for a layer. `--insecure-registry` allows plain http to any registry, and the plan then says so.

## Signature

The image's cosign signature is verified once its manifest is resolved, before any layer is downloaded. An unsigned image is refused with `no-signature`, since whoever can replace a tag can push the replacement without a signature. A signature that does not verify, or is not by the expected signer, is refused with `bad-signature`.

- By default the signer must be Kairos's release pipeline. That is a GitHub Actions workflow of `kairos-io/kairos`, or of `kairos-io/kairos-factory-action` for releases before v4.3.0, run for a release tag of `kairos-io/kairos`.
- Kairos signs the index of each release image keyless through Sigstore. From v4.3.0 on the signature is a sigstore bundle attached as an OCI referrer, before that a `.sig` tag. Both are read, the `.sig` tag when no bundle is a signature.
- For a tag reference, the release the signature was made for must be one of the tag's dash-separated parts: the last one, or one followed by more. For example, `v4.3.0` is in `v0.5.1-core-amd64-generic-v4.3.0`. So an older release, signed just as well, is refused under a newer release's tag. The signature does not cover the tag itself. Two flavors of one release for the same architecture, such as `generic` and `rpi4`, cannot be told apart by it.
- A digest reference is verified without the tag check. Kairos signs only the index, so pin the index digest. A pinned per-architecture manifest is refused as unsigned.
- The signature is looked up for the digest the registry returned, not by resolving the tag again. It is fetched with the same http and retry rules as the image. A mirror or cache that does not keep the signature gets the image refused as unsigned.
- Verification needs Sigstore's trusted root. It is fetched from `https://tuf-repo-cdn.sigstore.dev` over https, whatever `--insecure-registry` says, each file within a minute, and kept in memory only. Rekor is not asked. A machine that cannot reach the TUF repository needs `--trusted-root FILE`. One option is the `trusted_root.json` that `cosign initialize` leaves under `~/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/` on a machine that can.

### Signatures in a layout

A local image is verified against the sigstore bundles it holds as referrers, listed in its `index.json`. `oras copy --recursive IMAGE --to-oci-layout DIR:TAG` writes them that way. Copy the whole index without `--platform`, as only the index is signed. For `oci-archive:`, pack the directory with `tar --create --file FILE --directory DIR .`. A legacy `.sig` signature is not read from a layout. A layout carries no tag, so the tag check does not apply, and the plan names the release the signature is for.

### Other signers

`--verify-signature=false` installs the image without any of this, and the plan says so.

To accept another signer, for an image you build and sign yourself, pass two flags. `--signature-identity` is a regular expression the identity in the signing certificate must match. `--signature-issuer` is the OIDC issuer the certificate names. They work like `--certificate-identity-regexp` and `--certificate-oidc-issuer` of `cosign verify`. The expression matches anywhere in the identity unless anchored, so write `^https://github\.com/you/repo/` rather than `github.com/you/repo`. The checks on Kairos's repository and release then do not apply. Signatures made with a key rather than a Sigstore certificate are not accepted.
