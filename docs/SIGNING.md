# Signing and release trust

AntiOS release channels have different trust properties.

## Direct GitHub releases

Prerelease Windows binaries can be unsigned. When a release is unsigned, GitHub SHA-256 files verify file integrity but do **not** prove publisher identity.

Signed direct-download builds should be verified with Windows Authenticode in addition to checksum and provenance metadata.

## Microsoft Store

The Store package is built as an MSIX submission artifact. Microsoft signs accepted Store packages as part of the Store distribution process.

## Updates

An update that cannot be verified should not be treated as trusted just because it came from a familiar URL or filename.

Always read the release notes for the signing status of the build you are installing.
