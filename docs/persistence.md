# Persistence

Stage 1 has **no automatic persistence volume**.

The intended later design is a separate LUKS2-encrypted partition or USB device mounted only after explicit user authorization. Keeping persistence separate from the root overlay makes the trust boundary visible and avoids accidental retention.

Until that stage exists, do not place secrets on the base filesystem and assume they are safely persistent. OverlayFS is an amnesia mechanism, not encrypted storage.
