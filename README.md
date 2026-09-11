# streamheaders

A small library for parsing HTTP header blocks out of a stream, without
ever buffering the whole thing.

## the problem

Most header parsing code (including the stdlib's `email.parser`, which
`http.client` leans on) works by handing it a complete blob of bytes.
That's fine until you're the one reading off a live connection: you
either read the whole request into memory before you know how big it
is, or you write your own buffering loop by hand and get the edge
cases wrong (a header line split across two `recv()` calls, a client
trickling bytes in one at a time, an attacker who never sends the
terminating blank line at all).

`streamheaders` does the buffering loop for you. It reads from any
iterable of byte chunks - repeated `socket.recv()` calls, a file
object, anything - and only ever keeps the current line and the header
currently being assembled in memory. A slow or hostile sender can't
force it to buffer more than `max_line_size` bytes at once.

## usage

```python
from streamheaders import Headers, iter_headers

def recv_chunks(sock, size=4096):
    while True:
        chunk = sock.recv(size)
        if not chunk:
            return
        yield chunk

headers = Headers(iter_headers(recv_chunks(sock)))
print(headers.get("content-length"))
print(headers.get_all("set-cookie"))
```

Parsing stops as soon as it hits the blank line that ends the header
block, so `recv_chunks` (or whatever iterator you passed in) is left
positioned at the start of the body - keep reading from the same
generator to get it.

Reading from a file is the same shape:

```python
from streamheaders import iter_headers

with open("request.http", "rb") as f:
    def chunks():
        while True:
            data = f.read(4096)
            if not data:
                return
            yield data

    for name, value in iter_headers(chunks()):
        print(f"{name}: {value}")
```

`iter_headers` yields `(name, value)` pairs one at a time as they
complete, rather than waiting for the whole block, so a caller can act
on early headers (reject on `Content-Length` before the rest of the
request even arrives, say) without waiting for the parse to finish.

Going the other way, `Headers.to_bytes()` serializes a collection back
into a header block, including the terminating blank line:

```python
headers = Headers([("Content-Type", "text/plain"), ("X-Request-Id", "abc123")])
sock.sendall(headers.to_bytes())
```

`Headers.iter_encode()` gives you the same thing one line at a time,
if you'd rather write each line to a socket as it's produced instead
of building the whole block in memory first. Both raise `ValueError`
if a name or value can't be represented safely - a value containing a
bare CR or LF, for instance, which is how header injection attacks
smuggle an extra header or split the response.

## behavior worth knowing about

- Header field values are decoded as `latin-1`, not `utf-8` - that's
  what RFC 7230 actually specifies, even though nearly everything sent
  in practice is ASCII.
- Obsolete line folding (a continuation line starting with a space or
  tab) is rejected by default, since it's part of how request
  smuggling attacks confuse proxies about where one header ends and
  the next begins. Pass `allow_obsolete_folding=True` if you trust the
  source and need the compatibility.
- A space between a header name and its colon is rejected outright,
  for the same reason.
- `max_line_size` and `max_headers` are enforced so a stream that never
  sends a line terminator, or that sends thousands of tiny headers,
  can't be used to force unbounded memory or CPU use.

## status

Early skeleton. Parsing, encoding, and the `Headers` collection work
and are covered by the usage above and by the tests in `tests/`, but
there's no support yet for trailer headers after chunked
transfer-encoding.

Run the tests with `python -m unittest discover tests`.

## license

MIT, see `LICENSE`.
