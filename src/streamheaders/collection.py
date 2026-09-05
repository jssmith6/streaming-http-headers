"""A small case-insensitive, order-preserving header collection."""

from typing import Iterable, Iterator, List, Optional, Tuple

from .parser import _TOKEN_CHARS


def _check_name(name: str) -> None:
    if not name or any(ch not in _TOKEN_CHARS for ch in name):
        raise ValueError(f"invalid header name for encoding: {name!r}")


def _check_value(value: str) -> None:
    # A bare CR or LF in a value is exactly how header injection attacks
    # smuggle an extra header or split the response into two; refuse to
    # encode it rather than emit something a receiver could misparse.
    if "\r" in value or "\n" in value:
        raise ValueError(f"header value contains a line terminator: {value!r}")


class Headers:
    """Case-insensitive collection of header (name, value) pairs.

    Header names are compared case-insensitively per RFC 7230, but the
    original casing of each name is kept for output. Repeated names
    (Set-Cookie being the classic example) are preserved rather than
    the last one silently overwriting earlier ones.
    """

    def __init__(self, pairs: Iterable[Tuple[str, str]] = ()):
        self._items: List[Tuple[str, str]] = []
        for name, value in pairs:
            self.add(name, value)

    def add(self, name: str, value: str) -> None:
        self._items.append((name, value))

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        key = name.lower()
        for item_name, item_value in self._items:
            if item_name.lower() == key:
                return item_value
        return default

    def get_all(self, name: str) -> List[str]:
        key = name.lower()
        return [value for item_name, value in self._items if item_name.lower() == key]

    def __contains__(self, name: str) -> bool:
        key = name.lower()
        return any(item_name.lower() == key for item_name, _ in self._items)

    def __iter__(self) -> Iterator[Tuple[str, str]]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"Headers({self._items!r})"

    def iter_encode(self) -> Iterator[bytes]:
        """Serialize back to the wire format ``iter_headers`` parses.

        Yields one CRLF-terminated line per header, in insertion order,
        followed by the blank line that terminates a header block - so
        the concatenation of everything this yields is a complete,
        parseable header block on its own.
        """
        for name, value in self._items:
            _check_name(name)
            _check_value(value)
            yield f"{name}: {value}\r\n".encode("latin-1")
        yield b"\r\n"

    def to_bytes(self) -> bytes:
        """Serialize the whole collection, including the closing blank line."""
        return b"".join(self.iter_encode())
