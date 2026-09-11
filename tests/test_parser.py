import unittest

from streamheaders.parser import (
    HeaderError,
    HeaderLineTooLong,
    MalformedHeaderLine,
    TooManyHeaders,
    iter_headers,
)


def chunks_of(data: bytes, size: int):
    """Split data into fixed-size chunks, to exercise lines split across reads."""
    for i in range(0, len(data), size):
        yield data[i : i + size]


class BasicParsingTests(unittest.TestCase):
    def test_simple_crlf_block(self):
        block = b"Host: example.com\r\nContent-Length: 5\r\n\r\n"
        pairs = list(iter_headers([block]))
        self.assertEqual(
            pairs, [("Host", "example.com"), ("Content-Length", "5")]
        )

    def test_bare_lf_accepted(self):
        block = b"Host: example.com\nX-Id: 1\n\n"
        pairs = list(iter_headers([block]))
        self.assertEqual(pairs, [("Host", "example.com"), ("X-Id", "1")])

    def test_empty_block_yields_nothing(self):
        self.assertEqual(list(iter_headers([b"\r\n"])), [])

    def test_value_whitespace_is_stripped(self):
        block = b"X-Id:   1   \r\n\r\n"
        self.assertEqual(list(iter_headers([block])), [("X-Id", "1")])

    def test_value_may_be_empty(self):
        block = b"X-Empty:\r\n\r\n"
        self.assertEqual(list(iter_headers([block])), [("X-Empty", "")])

    def test_split_across_arbitrary_chunk_boundaries(self):
        block = b"Host: example.com\r\nX-Id: 12345\r\n\r\n"
        for size in range(1, len(block) + 1):
            pairs = list(iter_headers(chunks_of(block, size)))
            self.assertEqual(
                pairs, [("Host", "example.com"), ("X-Id", "12345")],
                msg=f"failed at chunk size {size}",
            )

    def test_latin1_value_decoding(self):
        # 0xE9 is e-acute in latin-1; RFC 7230 field values are ISO-8859-1.
        block = b"X-Name: caf\xe9\r\n\r\n"
        pairs = list(iter_headers([block]))
        self.assertEqual(pairs, [("X-Name", "caf\xe9")])


class ObsoleteFoldingTests(unittest.TestCase):
    def test_rejected_by_default(self):
        block = b"X-Long: first\r\n second\r\n\r\n"
        with self.assertRaises(MalformedHeaderLine):
            list(iter_headers([block]))

    def test_accepted_when_enabled(self):
        block = b"X-Long: first\r\n second\r\n\r\n"
        pairs = list(iter_headers([block], allow_obsolete_folding=True))
        self.assertEqual(pairs, [("X-Long", "first second")])

    def test_multiple_continuation_lines(self):
        block = b"X-Long: a\r\n b\r\n\tc\r\n\r\n"
        pairs = list(iter_headers([block], allow_obsolete_folding=True))
        self.assertEqual(pairs, [("X-Long", "a b c")])

    def test_continuation_as_first_line_is_malformed(self):
        block = b" leading\r\n\r\n"
        with self.assertRaises(MalformedHeaderLine):
            list(iter_headers([block], allow_obsolete_folding=True))


class OversizedLineTests(unittest.TestCase):
    def test_line_over_limit_raises(self):
        block = b"X-Big: " + b"a" * 100 + b"\r\n\r\n"
        with self.assertRaises(HeaderLineTooLong):
            list(iter_headers([block], max_line_size=32))

    def test_line_at_limit_is_fine(self):
        # max_line_size is only checked once the buffer *exceeds* it, so a
        # line whose length equals the limit must still parse successfully
        # even when delivered one byte at a time, forcing the size check to
        # run before the terminator ever shows up in the buffer.
        value = "a" * 20
        line = f"X-Ok: {value}".encode("ascii")
        block = line + b"\r\n\r\n"
        pairs = list(iter_headers(chunks_of(block, 1), max_line_size=len(line)))
        self.assertEqual(pairs, [("X-Ok", value)])

    def test_oversized_line_detected_across_many_small_chunks(self):
        block = b"X-Big: " + b"a" * 100 + b"\r\n\r\n"
        with self.assertRaises(HeaderLineTooLong):
            list(iter_headers(chunks_of(block, 1), max_line_size=32))


class TooManyHeadersTests(unittest.TestCase):
    def test_raises_past_limit(self):
        block = b"".join(f"X-{i}: {i}\r\n".encode() for i in range(5)) + b"\r\n"
        with self.assertRaises(TooManyHeaders):
            list(iter_headers([block], max_headers=3))

    def test_exactly_at_limit_is_fine(self):
        block = b"".join(f"X-{i}: {i}\r\n".encode() for i in range(3)) + b"\r\n"
        pairs = list(iter_headers([block], max_headers=3))
        self.assertEqual(len(pairs), 3)


class TruncatedStreamTests(unittest.TestCase):
    def test_stream_ends_without_blank_line(self):
        block = b"Host: example.com\r\n"
        with self.assertRaises(HeaderError):
            list(iter_headers([block]))

    def test_stream_ends_mid_line(self):
        block = b"Host: example.co"
        with self.assertRaises(HeaderError):
            list(iter_headers([block]))

    def test_empty_stream(self):
        with self.assertRaises(HeaderError):
            list(iter_headers([]))

    def test_generator_closes_before_terminator(self):
        def chunks():
            yield b"Host: example.com\r\n"
            yield b"X-Id: 1\r\n"

        with self.assertRaises(HeaderError):
            list(iter_headers(chunks()))


class MalformedLineTests(unittest.TestCase):
    def test_missing_colon(self):
        block = b"NotAHeader\r\n\r\n"
        with self.assertRaises(MalformedHeaderLine):
            list(iter_headers([block]))

    def test_whitespace_before_colon_rejected(self):
        block = b"X-Id : 1\r\n\r\n"
        with self.assertRaises(MalformedHeaderLine):
            list(iter_headers([block]))

    def test_invalid_character_in_name(self):
        block = b"X Id: 1\r\n\r\n"
        with self.assertRaises(MalformedHeaderLine):
            list(iter_headers([block]))

    def test_empty_name(self):
        block = b": 1\r\n\r\n"
        with self.assertRaises(MalformedHeaderLine):
            list(iter_headers([block]))


if __name__ == "__main__":
    unittest.main()
