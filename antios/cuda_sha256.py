"""Batched SHA-256 on Windows NVIDIA GPUs through the CUDA driver.

The driver assembles a small PTX kernel at runtime, so source and frozen builds
use the same implementation without requiring a CUDA Toolkit or Python wheel.
Digest labels and all detection policy stay on the caller's CPU.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes as C
import hashlib
import os
from collections.abc import Sequence
import struct
from threading import RLock


MAX_BATCH_BYTES = 16 * 1024 * 1024
MAX_BATCH_ITEMS = 4096
MAX_ITEM_BYTES = 1024 * 1024
_THREADS_PER_BLOCK = 128
_MAX_STAGED_BYTES = MAX_BATCH_BYTES + MAX_BATCH_ITEMS * 80
_PADDING = b"\x80" + bytes(71)

_INITIAL = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)
_CONSTANTS = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)


class CudaUnavailable(RuntimeError):
    """The optional CUDA backend cannot provide results for this batch."""


def _round_sigma(word, rotations, *, shift=False):
    """Emit one SHA-256 sigma expression in %x using %y and %z as scratch."""
    a, b, c = rotations
    tail = (
        f"shr.u32 %z, {word}, {c};" if shift
        else f"shf.r.wrap.b32 %z, {word}, {word}, {c};"
    )
    return [
        f"shf.r.wrap.b32 %x, {word}, {word}, {a};",
        f"shf.r.wrap.b32 %y, {word}, {word}, {b};",
        tail,
        "lop3.b32 %x, %x, %y, %z, 0x96;",  # XOR of three inputs
    ]


def _sha256_ptx():
    """Generate the FIPS 180-4 compression loop with a 16-register schedule."""
    lines = ["""
.version 6.0
.target sm_50
.address_size 64
.visible .entry antios_sha256(
    .param .u64 data, .param .u64 output, .param .u32 count
)
{
    .reg .pred %outside, %more;
    .reg .b32 %index, %count, %thread, %grid, %blocksize, %offset, %blocks;
    .reg .b32 %h<8>, %v<8>, %w<16>, %x, %y, %z, %t1, %t2;
    .reg .b64 %data, %output, %wide, %cursor;

    mov.u32 %thread, %tid.x;
    mov.u32 %grid, %ctaid.x;
    mov.u32 %blocksize, %ntid.x;
    mad.lo.u32 %index, %grid, %blocksize, %thread;
    ld.param.u32 %count, [count];
    setp.ge.u32 %outside, %index, %count;
    @%outside ret;
    ld.param.u64 %data, [data];
    cvta.to.global.u64 %data, %data;
    mul.wide.u32 %wide, %index, 8;
    add.u64 %cursor, %data, %wide;
    ld.global.v2.u32 {%offset, %blocks}, [%cursor];
    cvt.u64.u32 %wide, %offset;
    add.u64 %cursor, %data, %wide;
"""]
    for i, value in enumerate(_INITIAL):
        lines.append(f"mov.u32 %h{i}, {value:#x};")
    lines.append("compress_block:")
    for i in range(8):
        lines.append(f"mov.u32 %v{i}, %h{i};")
    for i in range(16):
        lines.extend((
            f"ld.global.u32 %w{i}, [%cursor+{i * 4}];",
            f"prmt.b32 %w{i}, %w{i}, 0, 0x0123;",  # big-endian input word
        ))
    registers = tuple(f"%v{i}" for i in range(8))
    for i, constant in enumerate(_CONSTANTS):
        a, b, c, d, e, f, g, h = registers
        word = f"%w{i % 16}"
        if i >= 16:
            lines.extend(_round_sigma(f"%w{(i - 15) % 16}", (7, 18, 3), shift=True))
            lines.append(f"add.u32 {word}, {word}, %x;")
            lines.extend(_round_sigma(f"%w{(i - 2) % 16}", (17, 19, 10), shift=True))
            lines.extend((
                f"add.u32 {word}, {word}, %w{(i - 7) % 16};",
                f"add.u32 {word}, {word}, %x;",
            ))
        lines.extend(_round_sigma(e, (6, 11, 25)))
        lines.extend((
            f"lop3.b32 %t1, {e}, {f}, {g}, 0xca;",  # Ch(e, f, g)
            f"add.u32 %t1, %t1, {h};",
            "add.u32 %t1, %t1, %x;",
            f"add.u32 %t1, %t1, {word};",
            f"add.u32 %t1, %t1, {constant:#x};",
        ))
        lines.extend(_round_sigma(a, (2, 13, 22)))
        lines.extend((
            f"lop3.b32 %t2, {a}, {b}, {c}, 0xe8;",  # Maj(a, b, c)
            "add.u32 %t2, %t2, %x;",
            f"add.u32 {d}, {d}, %t1;",
            f"add.u32 {h}, %t1, %t2;",
        ))
        registers = (h, a, b, c, d, e, f, g)
    for i, word in enumerate(registers):
        lines.append(f"add.u32 %h{i}, %h{i}, {word};")
    lines.append("""
    add.u64 %cursor, %cursor, 64;
    sub.u32 %blocks, %blocks, 1;
    setp.ne.u32 %more, %blocks, 0;
    @%more bra compress_block;
    ld.param.u64 %output, [output];
    cvta.to.global.u64 %output, %output;
    mul.wide.u32 %wide, %index, 32;
    add.u64 %cursor, %output, %wide;
""")
    for i in range(8):
        lines.extend((
            f"prmt.b32 %h{i}, %h{i}, 0, 0x0123;",
            f"st.global.u32 [%cursor+{i * 4}], %h{i};",
        ))
    return "\n".join([*lines, "ret;", "}"]).encode("ascii")


def _stage(contents, staged):
    # Every row starts with a byte offset and padded block count. Offsets and
    # words remain aligned so GPU reads do not rely on packed-struct behavior.
    headers = len(contents) * 8
    sizes = [((len(data) + 9 + 63) // 64) * 64 for data in contents]
    required = headers + sum(sizes)
    if len(staged) < required:
        staged = bytearray(min(_MAX_STAGED_BYTES, max(required, len(staged) * 2)))
    offset = headers
    view = memoryview(staged)
    for i, (data, padded_size) in enumerate(zip(contents, sizes)):
        struct.pack_into("<II", staged, i * 8, offset, padded_size // 64)
        data_end = offset + len(data)
        length_offset = offset + padded_size - 8
        view[offset:data_end] = data
        view[data_end:length_offset] = _PADDING[:length_offset - data_end]
        struct.pack_into(">Q", staged, length_offset, len(data) * 8)
        offset = length_offset + 8
    return staged, required


_P = C.c_void_p
_I = C.c_int
_U = C.c_uint32
_D = C.c_uint64
_N = C.c_size_t
_DRIVER_FUNCTIONS = {
    "cuInit": (_U,),
    "cuDeviceGet": (C.POINTER(_I), _I),
    "cuDeviceGetName": (_P, _I, _I),
    "cuDevicePrimaryCtxRetain": (C.POINTER(_P), _I),
    "cuDevicePrimaryCtxRelease_v2": (_I,),
    "cuCtxPushCurrent_v2": (_P,),
    "cuCtxPopCurrent_v2": (C.POINTER(_P),),
    "cuModuleLoadData": (C.POINTER(_P), _P),
    "cuModuleGetFunction": (C.POINTER(_P), _P, C.c_char_p),
    "cuModuleUnload": (_P,),
    "cuMemAlloc_v2": (C.POINTER(_D), _N),
    "cuMemFree_v2": (_D,),
    "cuMemcpyHtoD_v2": (_D, _P, _N),
    "cuMemcpyDtoH_v2": (_P, _D, _N),
    "cuLaunchKernel": (_P, _U, _U, _U, _U, _U, _U, _U, _P, C.POINTER(_P), C.POINTER(_P)),
    "cuCtxSynchronize": (),
}


class CudaSHA256:
    """A bounded and serialized driver-backed SHA-256 batch hasher."""

    name = "cuda-sha256"

    def __init__(self):
        self._lock = RLock()
        self._device = _I()
        self._context = _P()
        self._module = _P()
        self._kernel = _P()
        self._input = _D()
        self._output = _D()
        self._input_size = self._output_size = 0
        self._staged = bytearray()
        if os.name != "nt" or C.sizeof(_P) != 8:
            raise CudaUnavailable("CUDA SHA-256 currently requires 64-bit Windows")
        try:
            # The installed System32 driver is resolved at runtime. Keep it
            # outside frozen application payloads.
            driver_name = "nvcuda.dll"
            self._driver = C.WinDLL(driver_name, winmode=0x800)
            for name, argument_types in _DRIVER_FUNCTIONS.items():
                function = getattr(self._driver, name)
                function.argtypes = argument_types
                function.restype = _I
        except (AttributeError, OSError) as exc:
            raise CudaUnavailable("NVIDIA CUDA driver is unavailable") from exc
        try:
            self._call("cuInit", 0)
            self._call("cuDeviceGet", C.byref(self._device), 0)
            name = C.create_string_buffer(256)
            self._call("cuDeviceGetName", name, len(name), self._device)
            self.device_name = name.value.decode("utf-8", "replace")
            self._call("cuDevicePrimaryCtxRetain", C.byref(self._context), self._device)
            with self._current():
                image = C.create_string_buffer(_sha256_ptx())
                self._call("cuModuleLoadData", C.byref(self._module), image)
                self._call("cuModuleGetFunction", C.byref(self._kernel), self._module, b"antios_sha256")
            fixtures = (b"", b"abc", bytes(range(55)), bytes(range(56)), bytes(range(255)) * 5)
            if self.digest_many(fixtures) != tuple(hashlib.sha256(data).hexdigest() for data in fixtures):
                raise CudaUnavailable("CUDA SHA-256 startup parity check failed")
        except BaseException:
            self.close()
            raise

    def _call(self, name, *args):
        result = getattr(self._driver, name)(*args)
        if result:
            raise CudaUnavailable(f"CUDA call {name} failed ({result})")

    @contextmanager
    def _current(self):
        self._call("cuCtxPushCurrent_v2", self._context)
        try:
            yield
        finally:
            popped = _P()
            self._call("cuCtxPopCurrent_v2", C.byref(popped))

    def _reserve(self, address, old_size, size, maximum):
        if address.value and old_size >= size:
            return old_size
        if address.value:
            self._call("cuMemFree_v2", address)
            address.value = 0
        capacity = min(maximum, max(size, old_size * 2))
        self._call("cuMemAlloc_v2", C.byref(address), capacity)
        return capacity

    def digest_many(self, contents: Sequence[bytes]) -> tuple[str, ...]:
        if len(contents) > MAX_BATCH_ITEMS:
            raise ValueError("CUDA SHA-256 item budget exceeded")
        contents = tuple(contents)
        if len(contents) > MAX_BATCH_ITEMS:
            raise ValueError("CUDA SHA-256 item budget exceeded")
        if not contents:
            return ()
        if any(not isinstance(data, bytes) or len(data) > MAX_ITEM_BYTES for data in contents):
            raise ValueError("CUDA SHA-256 expects bounded byte strings")
        if sum(map(len, contents)) > MAX_BATCH_BYTES:
            raise ValueError("CUDA SHA-256 byte budget exceeded")
        with self._lock:
            if not self._context.value:
                raise CudaUnavailable("CUDA SHA-256 backend is closed")
            self._staged, input_size = _stage(contents, self._staged)
            host_input = (C.c_char * input_size).from_buffer(self._staged)
            output_size = len(contents) * 32
            host_output = C.create_string_buffer(output_size)
            with self._current():
                self._input_size = self._reserve(self._input, self._input_size, input_size, _MAX_STAGED_BYTES)
                self._output_size = self._reserve(self._output, self._output_size, output_size, MAX_BATCH_ITEMS * 32)
                self._call("cuMemcpyHtoD_v2", self._input, host_input, input_size)
                count = _U(len(contents))
                parameters = (_P * 3)(C.addressof(self._input), C.addressof(self._output), C.addressof(count))
                blocks = (len(contents) + _THREADS_PER_BLOCK - 1) // _THREADS_PER_BLOCK
                self._call("cuLaunchKernel", self._kernel, blocks, 1, 1, _THREADS_PER_BLOCK, 1, 1, 0, None,
                           parameters, None)
                self._call("cuCtxSynchronize")
                self._call("cuMemcpyDtoH_v2", host_output, self._output, output_size)
            data = host_output.raw
            return tuple(data[i:i + 32].hex() for i in range(0, output_size, 32))

    def close(self):
        """Release only the resources owned by this backend."""
        with self._lock:
            if not self._context.value:
                return
            try:
                with self._current():
                    for address in (self._input, self._output):
                        if address.value:
                            self._driver.cuMemFree_v2(address)
                    if self._module.value:
                        self._driver.cuModuleUnload(self._module)
            except CudaUnavailable:
                pass  # Failed CUDA contexts can reject cleanup calls.
            finally:
                self._driver.cuDevicePrimaryCtxRelease_v2(self._device)
                self._context.value = None
                self._staged = bytearray()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
