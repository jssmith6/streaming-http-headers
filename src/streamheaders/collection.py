"""A small case-insensitive, order-preserving header collection."""

from typing import Iterable, Iterator, List, Optional, Tuple


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
