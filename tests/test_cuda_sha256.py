from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
import random
import struct

import pytest

from antios.cuda_sha256 import (
    MAX_BATCH_BYTES, MAX_BATCH_ITEMS, MAX_ITEM_BYTES, CudaSHA256, CudaUnavailable, _stage,
)


def test_staged_batch_has_aligned_offsets_and_exact_sha256_padding():
    inputs = (b"", b"\0" * 55, b"\xaa" * 56, b"\xff" * 64)
    previous = bytearray(b"\xff" * 2048)
    staged, size = _stage(inputs, previous)
    assert staged is previous
    next_offset = 8 * len(inputs)
    for index, data in enumerate(inputs):
        offset, blocks = struct.unpack_from("<II", staged, index * 8)
        assert offset == next_offset and offset % 8 == 0
        next_offset = offset + blocks * 64
        assert staged[offset:offset + len(data)] == data
        assert staged[offset + len(data)] == 0x80
        assert not any(staged[offset + len(data) + 1:next_offset - 8])
        assert struct.unpack_from(">Q", staged, next_offset - 8)[0] == len(data) * 8
    assert next_offset == size


def test_invalid_gpu_batch_fails_before_driver_access():
    backend = CudaSHA256.__new__(CudaSHA256)
    with pytest.raises(ValueError, match="item budget"):
        backend.digest_many((b"",) * (MAX_BATCH_ITEMS + 1))
    with pytest.raises(ValueError, match="bounded byte strings"):
        backend.digest_many((b"x" * (MAX_ITEM_BYTES + 1),))
    with pytest.raises(ValueError, match="byte budget"):
        backend.digest_many((b"x" * MAX_ITEM_BYTES,) * (MAX_BATCH_BYTES // MAX_ITEM_BYTES + 1))


def test_cuda_sha256_matches_hashlib_with_batch_reuse_and_threads():
    try:
        gpu = CudaSHA256()
    except CudaUnavailable as exc:
        if os.environ.get("ANTIOS_TEST_CUDA") == "1":
            raise
        pytest.skip(str(exc))
    rng = random.Random(297)
    lengths = (0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 511, 4096, MAX_ITEM_BYTES)
    small_batches = [tuple(rng.randbytes(length) for length in lengths[:-1]) for _ in range(4)]
    big_batch = tuple(rng.randbytes(length) for length in lengths)
    with gpu, ThreadPoolExecutor(max_workers=4) as executor:
        assert gpu.digest_many(big_batch) == tuple(hashlib.sha256(data).hexdigest() for data in big_batch)
        for inputs, result in zip(small_batches, executor.map(gpu.digest_many, small_batches)):
            assert result == tuple(hashlib.sha256(data).hexdigest() for data in inputs)
    with pytest.raises(CudaUnavailable, match="closed"):
        gpu.digest_many((b"x",))
