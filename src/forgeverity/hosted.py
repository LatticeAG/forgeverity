"""Hosted/paid surfaces are NOT part of the OSS core. These interfaces exist
so callers can depend on the contract today; every method raises
NotImplementedError with a documentation pointer instead of pretending to
work. See https://docs.latticeagi.dev/forgeverity/hosted"""

_DOC = "https://docs.latticeagi.dev/forgeverity/hosted"


class HostedScorer:
    """Cloud scoring (GPU metrics, embedding diversity) — hosted only."""

    def score(self, *_args, **_kwargs):
        raise NotImplementedError(
            f"Hosted scoring is not in the OSS core. See {_DOC}"
        )


class HostedVerifier:
    """Remote attestation of model execution — hosted only."""

    def attest(self, *_args, **_kwargs):
        raise NotImplementedError(
            f"Remote attestation is not in the OSS core. See {_DOC}"
        )


class HostedAuditMirror:
    """Managed audit-log mirroring — hosted only."""

    def mirror(self, *_args, **_kwargs):
        raise NotImplementedError(
            f"Managed audit mirroring is not in the OSS core. See {_DOC}"
        )
