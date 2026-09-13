"""Streaming parser for HTTP header blocks.

The point of this module is that none of it ever holds the full header
block, let alone the full request or response, in memory. It only ever
holds one line (bounded by max_line_size) and the header currently being
assembled. That matters for anything reading off a live socket, where an
attacker (or just a buggy client) can otherwise be used to force
unbounded buffering.
"""

from typing import Iterable, Iterator, List, Tuple


class HeaderError(Exception):
    """Base class for errors raised while parsing a header block."""


class HeaderLineTooLong(HeaderError):
    """A line exceeded max_line_size before a terminator was found."""


class TooManyHeaders(HeaderError):
    """The header block contained more fields than max_headers allows."""


class MalformedHeaderLine(HeaderError):
    """A line did not look like a valid HTTP header field."""


class MalformedChunkedBody(HeaderError):
    """A chunked-transfer-encoding body did not follow RFC 7230 4.1 framing."""


class ChunkTooLarge(HeaderError):
    """A chunk-size line declared more data than max_chunk_size allows."""


# RFC 7230 section 3.2.6 token characters, i.e. what's legal in a header
# field name. Rejecting anything outside this set up front avoids having
# to reason about weird bytes later on.
_TOKEN_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


class LineReader:
    """Pulls newline-terminated lines out of an iterable of byte chunks.

    Keeps at most one partial line buffered between chunks, so memory
    use is bounded by max_line_size no matter how large the underlying
    stream is. Accepts both CRLF and bare LF line endings.
    """

    def __init__(self, chunks: Iterable[bytes], max_line_size: int = 8192):
        self._chunks = iter(chunks)
        self._max_line_size = max_line_size
        self._buffer = bytearray()
        self._exhausted = False

    def __iter__(self) -> "LineReader":
        return self

    def __next__(self) -> bytes:
        while True:
            newline_pos = self._buffer.find(b"\n")
            if newline_pos != -1:
                line = bytes(self._buffer[:newline_pos])
                del self._buffer[: newline_pos + 1]
                if line.endswith(b"\r"):
                    line = line[:-1]
                return line

            if len(self._buffer) > self._max_line_size:
                raise HeaderLineTooLong(
                    f"header line exceeded {self._max_line_size} bytes "
                    "without a line terminator"
                )

            if self._exhausted:
                if self._buffer:
                    line = bytes(self._buffer)
                    self._buffer.clear()
                    if line.endswith(b"\r"):
                        line = line[:-1]
                    return line
                raise StopIteration

            try:
                chunk = next(self._chunks)
            except StopIteration:
                self._exhausted = True
                continue
            self._buffer.extend(chunk)

    def read_exact(self, size: int) -> bytes:
        """Read exactly ``size`` raw bytes, bypassing line splitting.

        Used for chunk payloads in chunked transfer-encoding, where the
        data is arbitrary bytes and may itself contain newlines.
        """
        while len(self._buffer) < size:
            if self._exhausted:
                raise HeaderError(
                    "stream ended before expected chunk data was fully read"
                )
            try:
                chunk = next(self._chunks)
            except StopIteration:
                self._exhausted = True
                continue
            self._buffer.extend(chunk)
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data


def _validate_name(raw: bytes) -> str:
    if not raw:
        raise MalformedHeaderLine("empty header name")
    try:
        name = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise MalformedHeaderLine(f"non-ASCII header name {raw!r}") from exc
    if any(ch not in _TOKEN_CHARS for ch in name):
        raise MalformedHeaderLine(f"invalid character in header name {raw!r}")
    return name


def _raw_pairs(
    reader: LineReader, allow_obsolete_folding: bool
) -> Iterator[Tuple[str, str]]:
    pending_name = None
    pending_value = None

    for line in reader:
        if not line:
            if pending_name is not None:
                yield pending_name, pending_value
            return

        if line[0] in b" \t":
            if pending_name is None:
                raise MalformedHeaderLine(
                    "header block cannot start with a continuation line"
                )
            if not allow_obsolete_folding:
                raise MalformedHeaderLine(
                    "obsolete line folding is disabled by default; header "
                    "smuggling attacks lean on it, so pass "
                    "allow_obsolete_folding=True only if you trust the source"
                )
            # RFC 7230 3.2.4: a folded line is replaced with a single space
            # plus its (stripped) content, joined onto the previous value.
            pending_value += " " + line.strip(b" \t").decode("latin-1")
            continue

        if pending_name is not None:
            yield pending_name, pending_value

        name_bytes, sep, value_bytes = line.partition(b":")
        if not sep:
            raise MalformedHeaderLine(f"missing colon in header line {line!r}")
        if name_bytes[-1:] in b" \t":
            # A space before the colon is what request-smuggling exploits
            # rely on proxies disagreeing about; refuse it outright.
            raise MalformedHeaderLine(
                f"whitespace before colon in header line {line!r}"
            )
        pending_name = _validate_name(name_bytes)
        # Header field values are formally ISO-8859-1 (RFC 7230 3.2), not
        # UTF-8, even though almost everything sent in practice is ASCII.
        pending_value = value_bytes.strip(b" \t").decode("latin-1")

    raise HeaderError("stream ended before the header block was terminated")


def _limited_pairs(
    reader: LineReader, allow_obsolete_folding: bool, max_headers: int
) -> Iterator[Tuple[str, str]]:
    for count, pair in enumerate(_raw_pairs(reader, allow_obsolete_folding), start=1):
        if count > max_headers:
            raise TooManyHeaders(f"more than {max_headers} headers in block")
        yield pair


def iter_headers(
    chunks: Iterable[bytes],
    *,
    max_line_size: int = 8192,
    max_headers: int = 100,
    allow_obsolete_folding: bool = False,
) -> Iterator[Tuple[str, str]]:
    """Parse an HTTP header block out of a stream of byte chunks.

    ``chunks`` is any iterable of bytes - repeated socket.recv() calls,
    a binary file object, whatever. Parsing stops at the blank line that
    terminates the header block, so the same iterator can keep being
    read from afterwards to get the body.

    Yields (name, value) pairs as soon as each one is complete, so a
    caller can start acting on headers (e.g. rejecting a request based
    on Content-Length) before the rest of the block has even arrived.
    """
    reader = LineReader(chunks, max_line_size=max_line_size)
    yield from _limited_pairs(reader, allow_obsolete_folding, max_headers)


_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _parse_chunk_size(line: bytes) -> int:
    # A chunk-size line may carry chunk-extensions after a ';' (RFC 7230
    # 4.1.1); nothing in this library needs them, so they're discarded.
    field = line.split(b";", 1)[0].strip()
    if not field or any(chr(b) not in _HEX_DIGITS for b in field):
        raise MalformedChunkedBody(f"invalid chunk size line {line!r}")
    return int(field, 16)


class ChunkedBodyReader:
    """Decodes an HTTP chunked-transfer-encoding body (RFC 7230 4.1).

    Iterate over an instance to get the decoded body as it arrives, one
    chunk's worth of bytes at a time. Once iteration ends, ``trailers``
    holds any trailer header fields sent after the terminating
    zero-length chunk, as (name, value) pairs - empty if none were
    sent, since a trailer section is optional even for a chunked body.

    Like the rest of this library, memory use is bounded: at most one
    chunk's data (up to max_chunk_size) and one line are held at once.
    """

    def __init__(
        self,
        chunks: Iterable[bytes],
        *,
        max_line_size: int = 8192,
        max_chunk_size: int = 1024 * 1024,
        max_headers: int = 100,
        allow_obsolete_folding: bool = False,
    ):
        self._reader = LineReader(chunks, max_line_size=max_line_size)
        self._max_chunk_size = max_chunk_size
        self._max_headers = max_headers
        self._allow_obsolete_folding = allow_obsolete_folding
        self._done = False
        self.trailers: List[Tuple[str, str]] = []

    def __iter__(self) -> "ChunkedBodyReader":
        return self

    def __next__(self) -> bytes:
        if self._done:
            raise StopIteration

        try:
            size_line = next(self._reader)
        except StopIteration:
            # A bare StopIteration here would look like a well-formed,
            # merely short body instead of a stream that broke off mid
            # chunk; raise so truncation can't pass for a valid ending.
            raise HeaderError(
                "stream ended before a chunk-size line was found"
            ) from None
        size = _parse_chunk_size(size_line)
        if size > self._max_chunk_size:
            raise ChunkTooLarge(
                f"chunk of {size} bytes exceeds max_chunk_size "
                f"{self._max_chunk_size}"
            )

        if size == 0:
            self._done = True
            self.trailers = list(
                _limited_pairs(
                    self._reader, self._allow_obsolete_folding, self._max_headers
                )
            )
            raise StopIteration

        data = self._reader.read_exact(size)
        try:
            trailer = next(self._reader)
        except StopIteration:
            raise HeaderError(
                "stream ended before the terminator after chunk data"
            ) from None
        if trailer:
            raise MalformedChunkedBody(
                f"chunk data not followed by a bare line terminator, got {trailer!r}"
            )
        return data
