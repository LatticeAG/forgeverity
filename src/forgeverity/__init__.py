"""ForgeVerity: the LatticeAG provenance gate for synthetic support-ticket
batches. Owns filter → provenance-tag → diversity/collapse gate → accept or
reject. Does not generate data, does not train models."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("forgeverity")
except PackageNotFoundError:
    # Running from a source checkout without installed dist metadata.
    # Keep in sync with pyproject.toml [project] version.
    __version__ = "1.0.0"
