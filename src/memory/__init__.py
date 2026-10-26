"""Memory: a local encrypted memory store for one owner."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("memory")
except PackageNotFoundError:  # pragma: no cover - editable installs provide metadata
    __version__ = "1.13.0"


__all__ = ["__version__"]
