import unittest

from streamheaders.parser import (
    ChunkedBodyReader,
    ChunkTooLarge,
    HeaderError,
    MalformedChunkedBody,
    TooManyHeaders,
)


def chunks_of(data: bytes, size: int):
    for i in range(0, len(data), size):
        yield data[i : i + size]


class ChunkedBodyTests(unittest.TestCase):
    def test_single_chunk(self):
        body = b"5\r\nhello\r\n0\r\n\r\n"
        reader = ChunkedBodyReader([body])
        self.assertEqual(list(reader), [b"hello"])
        self.assertEqual(reader.trailers, [])

    def test_multiple_chunks(self):
        body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        reader = ChunkedBodyReader([body])
        self.assertEqual(list(reader), [b"hello", b" world"])

    def test_empty_body(self):
        reader = ChunkedBodyReader([b"0\r\n\r\n"])
        self.assertEqual(list(reader), [])
        self.assertEqual(reader.trailers, [])

    def test_split_across_arbitrary_chunk_boundaries(self):
        body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        for size in range(1, len(body) + 1):
            reader = ChunkedBodyReader(chunks_of(body, size))
            self.assertEqual(
                list(reader), [b"hello", b" world"], msg=f"failed at size {size}"
            )

    def test_chunk_size_is_hexadecimal(self):
        body = b"a\r\n0123456789\r\n0\r\n\r\n"
        reader = ChunkedBodyReader([body])
        self.assertEqual(list(reader), [b"0123456789"])

    def test_chunk_extension_is_ignored(self):
        body = b"5;foo=bar\r\nhello\r\n0\r\n\r\n"
        reader = ChunkedBodyReader([body])
        self.assertEqual(list(reader), [b"hello"])

    def test_chunk_data_may_contain_newlines(self):
        data = b"a\nb\rc\r\n"
        size = f"{len(data):x}".encode()
        body = size + b"\r\n" + data + b"\r\n0\r\n\r\n"
        reader = ChunkedBodyReader([body])
        self.assertEqual(list(reader), [data])


class TrailerTests(unittest.TestCase):
    def test_trailers_are_collected(self):
        body = b"5\r\nhello\r\n0\r\nX-Checksum: abc123\r\nX-Trace: 1\r\n\r\n"
        reader = ChunkedBodyReader([body])
        self.assertEqual(list(reader), [b"hello"])
        self.assertEqual(
            reader.trailers, [("X-Checksum", "abc123"), ("X-Trace", "1")]
        )

    def test_no_trailers_means_empty_list(self):
        reader = ChunkedBodyReader([b"3\r\nabc\r\n0\r\n\r\n"])
        list(reader)
        self.assertEqual(reader.trailers, [])

    def test_too_many_trailers_raises(self):
        trailers = b"".join(f"X-{i}: {i}\r\n".encode() for i in range(5))
        body = b"0\r\n" + trailers + b"\r\n"
        reader = ChunkedBodyReader([body], max_headers=3)
        with self.assertRaises(TooManyHeaders):
            list(reader)


class ChunkedBodyErrorTests(unittest.TestCase):
    def test_invalid_chunk_size_line(self):
        reader = ChunkedBodyReader([b"not-hex\r\nhello\r\n0\r\n\r\n"])
        with self.assertRaises(MalformedChunkedBody):
            list(reader)

    def test_chunk_exceeding_max_size_raises(self):
        body = b"ffffffff\r\n" + b"a" * 16 + b"\r\n0\r\n\r\n"
        reader = ChunkedBodyReader([body], max_chunk_size=1024)
        with self.assertRaises(ChunkTooLarge):
            list(reader)

    def test_missing_terminator_after_chunk_data(self):
        body = b"5\r\nhelloXX0\r\n\r\n"
        reader = ChunkedBodyReader([body])
        with self.assertRaises(MalformedChunkedBody):
            list(reader)

    def test_truncated_stream_mid_chunk(self):
        reader = ChunkedBodyReader([b"a\r\nhello"])
        with self.assertRaises(HeaderError):
            list(reader)

    def test_truncated_stream_before_trailer_terminator(self):
        reader = ChunkedBodyReader([b"0\r\nX-Id: 1\r\n"])
        with self.assertRaises(HeaderError):
            list(reader)

    def test_stream_ends_without_terminating_chunk(self):
        # The body just stops after a complete, well-formed chunk - no
        # "0\r\n\r\n" ever arrives. That must not look like a short-but-
        # valid body.
        reader = ChunkedBodyReader([b"5\r\nhello\r\n"])
        with self.assertRaises(HeaderError):
            list(reader)

    def test_empty_stream(self):
        reader = ChunkedBodyReader([])
        with self.assertRaises(HeaderError):
            list(reader)


if __name__ == "__main__":
    unittest.main()
