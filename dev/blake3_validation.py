#!/usr/bin/env python3
"""Verification procedures for the optimized BLAKE3 implementation.

Procedures
----------
V1  Official test vectors – all 35 BLAKE3-team vectors in hash, keyed_hash and
    derive_key modes, full 131-byte extended output, checked against both the
    native package and an independent pure-Python reference implementation.
V2  Independent cross-implementation check – native package vs the reference
    implementation on seeded random inputs that cross block, chunk and tree
    boundaries.
V3  Configuration consistency – the same input must yield one digest under
    every buffer size, thread count, I/O path (stream, mmap, in-memory, small-
    file batch worker) and every factorial configuration of the study.

Hash-behaviour tests of thesis Section 3.5 (computed through the optimized
engine path):

H1  Collision test - identical digests among 10,000 distinct random inputs,
    collision rate CR (Eq. 15).
H2  Avalanche effect - one bit flipped in each of 1,000 random inputs,
    AE = HD / 256 x 100 (Eq. 13), expected close to 50 %.
H3  Hash distribution - chi-square of the byte values of the same 10,000
    digests against a uniform distribution (Eq. 14), not significant at 0.05.
H4  Deterministic output - each input hashed ten times, D (Eq. 16) = 100 %.

Scope of conclusions
--------------------
V1-V3 establish that *this implementation and its optimizations* compute
standard BLAKE3 correctly. H1-H4 are supporting observations that the outputs
behave as expected on the tested inputs. None of them
proves collision resistance, preimage resistance, or any other security
property; those rest on the published cryptanalysis of BLAKE3, which this
study neither modifies nor re-evaluates.
"""

from __future__ import annotations

import argparse
import io
import json
import math
import os
import random
import statistics
import tempfile
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

import blake3

from benchmark_blake3 import chi_square_sf
from optimized_blake3 import (
    BLAKE3_CONFIGS,
    MIB,
    SMALL_FILE_LIMIT,
    _small_batch_worker,
    _small_file_worker,
    hash_file,
    hash_file_config,
    hash_stream,
    hash_stream_profile,
    serve_forever,
    STREAM_CONFIG_PROFILES,
    logical_cpu_count,
    physical_cpu_count,
    self_test,
)

VECTOR_PATH = Path(__file__).resolve().parent / "test_vectors" / "test_vectors.json"
VECTOR_SOURCE = ("https://github.com/BLAKE3-team/BLAKE3/blob/master/"
                 "test_vectors/test_vectors.json")
Z_CRITICAL = 3.29  # two-sided p = 0.001
CONSISTENCY_MAX_FILE_BYTES = 1024 * MIB
CONSISTENCY_SAMPLE_BYTES = 512 * MIB

LIMITATIONS = (
    "These procedures verify that this implementation computes standard BLAKE3 "
    "correctly under every optimization, and that its outputs behave as expected on "
    "the tested inputs. They do not prove collision or preimage resistance; BLAKE3's "
    "security rests on its published design and cryptanalysis, which this study does "
    "not modify."
)

ProgressCallback = Optional[Callable[[str, float], None]]


# ─────────────────────────────────────────────────────────────────────────────
# Independent pure-Python BLAKE3 reference implementation
# ─────────────────────────────────────────────────────────────────────────────
# Independent pure-Python BLAKE3 reference implementation.
#
# This is a direct, line-by-line port of the BLAKE3 team's specification
# reference implementation (``reference_impl/reference_impl.rs`` in
# https://github.com/BLAKE3-team/BLAKE3).  It shares *no code* with the native
# ``blake3`` package used by the optimized engine, so agreement between the two
# is evidence of implementation correctness, not just
# self-consistency.
#
# It is intentionally simple and slow (roughly 1 MiB/s): it is used only for
# verification, never for evidence hashing or benchmarking.

OUT_LEN = 32
KEY_LEN = 32
BLOCK_LEN = 64
CHUNK_LEN = 1024

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
KEYED_HASH = 1 << 4
DERIVE_KEY_CONTEXT = 1 << 5
DERIVE_KEY_MATERIAL = 1 << 6

IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
MASK = 0xFFFFFFFF


def _rotr(value: int, amount: int) -> int:
    return ((value >> amount) | (value << (32 - amount))) & MASK


def _g(state: List[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    state[a] = (state[a] + state[b] + mx) & MASK
    state[d] = _rotr(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = _rotr(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & MASK
    state[d] = _rotr(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = _rotr(state[b] ^ state[c], 7)


def _round(state: List[int], m: List[int]) -> None:
    # Mix the columns.
    _g(state, 0, 4, 8, 12, m[0], m[1])
    _g(state, 1, 5, 9, 13, m[2], m[3])
    _g(state, 2, 6, 10, 14, m[4], m[5])
    _g(state, 3, 7, 11, 15, m[6], m[7])
    # Mix the diagonals.
    _g(state, 0, 5, 10, 15, m[8], m[9])
    _g(state, 1, 6, 11, 12, m[10], m[11])
    _g(state, 2, 7, 8, 13, m[12], m[13])
    _g(state, 3, 4, 9, 14, m[14], m[15])


def _permute(m: List[int]) -> List[int]:
    return [m[MSG_PERMUTATION[i]] for i in range(16)]


def _compress(
    chaining_value: List[int],
    block_words: List[int],
    counter: int,
    block_len: int,
    flags: int,
) -> List[int]:
    state = [
        *chaining_value[:8],
        IV[0], IV[1], IV[2], IV[3],
        counter & MASK, (counter >> 32) & MASK, block_len, flags,
    ]
    block = list(block_words)
    for round_index in range(7):
        _round(state, block)
        if round_index < 6:
            block = _permute(block)
    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= chaining_value[i]
    return state


def _words_from_le_bytes(data: bytes) -> List[int]:
    return [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]


class _Output:
    def __init__(self, input_cv, block_words, counter, block_len, flags):
        self.input_chaining_value = input_cv
        self.block_words = block_words
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value(self) -> List[int]:
        return _compress(
            self.input_chaining_value, self.block_words,
            self.counter, self.block_len, self.flags,
        )[:8]

    def root_output_bytes(self, length: int) -> bytes:
        out = bytearray()
        output_block_counter = 0
        while len(out) < length:
            words = _compress(
                self.input_chaining_value, self.block_words,
                output_block_counter, self.block_len, self.flags | ROOT,
            )
            for word in words:
                out += word.to_bytes(4, "little")
            output_block_counter += 1
        return bytes(out[:length])


class _ChunkState:
    def __init__(self, key_words: List[int], chunk_counter: int, flags: int):
        self.chaining_value = list(key_words)
        self.chunk_counter = chunk_counter
        self.block = bytearray(BLOCK_LEN)
        self.block_len = 0
        self.blocks_compressed = 0
        self.flags = flags

    def length(self) -> int:
        return BLOCK_LEN * self.blocks_compressed + self.block_len

    def _start_flag(self) -> int:
        return CHUNK_START if self.blocks_compressed == 0 else 0

    def update(self, data: memoryview) -> None:
        while len(data):
            if self.block_len == BLOCK_LEN:
                block_words = _words_from_le_bytes(bytes(self.block))
                self.chaining_value = _compress(
                    self.chaining_value, block_words, self.chunk_counter,
                    BLOCK_LEN, self.flags | self._start_flag(),
                )[:8]
                self.blocks_compressed += 1
                self.block = bytearray(BLOCK_LEN)
                self.block_len = 0
            want = BLOCK_LEN - self.block_len
            take = min(want, len(data))
            self.block[self.block_len:self.block_len + take] = data[:take]
            self.block_len += take
            data = data[take:]

    def output(self) -> _Output:
        block_words = _words_from_le_bytes(bytes(self.block))
        return _Output(
            self.chaining_value, block_words, self.chunk_counter,
            self.block_len, self.flags | self._start_flag() | CHUNK_END,
        )


def _parent_output(left_cv, right_cv, key_words, flags) -> _Output:
    return _Output(key_words, list(left_cv) + list(right_cv), 0, BLOCK_LEN, PARENT | flags)


class ReferenceHasher:
    """Incremental BLAKE3 hasher (hash, keyed_hash, derive_key modes)."""

    def __init__(self, key_words: Optional[List[int]] = None, flags: int = 0):
        self.key_words = list(key_words) if key_words is not None else list(IV)
        self.flags = flags
        self.chunk_state = _ChunkState(self.key_words, 0, flags)
        self.cv_stack: List[List[int]] = []

    @classmethod
    def new_keyed(cls, key: bytes) -> "ReferenceHasher":
        if len(key) != KEY_LEN:
            raise ValueError("key must be exactly 32 bytes")
        return cls(_words_from_le_bytes(key), KEYED_HASH)

    @classmethod
    def new_derive_key(cls, context: str) -> "ReferenceHasher":
        context_hasher = cls(list(IV), DERIVE_KEY_CONTEXT)
        context_hasher.update(context.encode("utf-8"))
        context_key = context_hasher.finalize(KEY_LEN)
        return cls(_words_from_le_bytes(context_key), DERIVE_KEY_MATERIAL)

    def _add_chunk_chaining_value(self, new_cv: List[int], total_chunks: int) -> None:
        # Merge completed subtrees: one merge per trailing zero bit.
        while total_chunks & 1 == 0:
            new_cv = _parent_output(
                self.cv_stack.pop(), new_cv, self.key_words, self.flags
            ).chaining_value()
            total_chunks >>= 1
        self.cv_stack.append(new_cv)

    def update(self, data: bytes) -> "ReferenceHasher":
        view = memoryview(bytes(data))
        while len(view):
            if self.chunk_state.length() == CHUNK_LEN:
                chunk_cv = self.chunk_state.output().chaining_value()
                total_chunks = self.chunk_state.chunk_counter + 1
                self._add_chunk_chaining_value(chunk_cv, total_chunks)
                self.chunk_state = _ChunkState(self.key_words, total_chunks, self.flags)
            want = CHUNK_LEN - self.chunk_state.length()
            take = min(want, len(view))
            self.chunk_state.update(view[:take])
            view = view[take:]
        return self

    def finalize(self, length: int = OUT_LEN) -> bytes:
        output = self.chunk_state.output()
        parent_nodes_remaining = len(self.cv_stack)
        while parent_nodes_remaining > 0:
            parent_nodes_remaining -= 1
            output = _parent_output(
                self.cv_stack[parent_nodes_remaining],
                output.chaining_value(),
                self.key_words,
                self.flags,
            )
        return output.root_output_bytes(length)


def reference_hash(data: bytes, length: int = OUT_LEN) -> bytes:
    return ReferenceHasher().update(data).finalize(length)


def reference_keyed_hash(key: bytes, data: bytes, length: int = OUT_LEN) -> bytes:
    return ReferenceHasher.new_keyed(key).update(data).finalize(length)


def reference_derive_key(context: str, material: bytes, length: int = OUT_LEN) -> bytes:
    return ReferenceHasher.new_derive_key(context).update(material).finalize(length)




def _vector_input(length: int) -> bytes:
    return bytes(i % 251 for i in range(length))


# ── V1 ──────────────────────────────────────────────────────────────────────

def official_test_vectors(path: Path = VECTOR_PATH) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    key = data["key"].encode("ascii")
    context = data["context_string"]
    cases = []
    failures = 0
    for case in data["cases"]:
        payload = _vector_input(case["input_len"])
        length = len(case["hash"]) // 2
        checks = {
            "native_hash": blake3.blake3(payload).digest(length).hex() == case["hash"],
            "native_keyed": blake3.blake3(payload, key=key).digest(length).hex() == case["keyed_hash"],
            "native_derive": blake3.blake3(payload, derive_key_context=context)
            .digest(length).hex() == case["derive_key"],
            "native_multithread": blake3.blake3(payload, max_threads=blake3.blake3.AUTO)
            .digest(length).hex() == case["hash"],
            "reference_hash": reference_hash(payload, length).hex() == case["hash"],
            "reference_keyed": reference_keyed_hash(key, payload, length).hex() == case["keyed_hash"],
            "reference_derive": reference_derive_key(context, payload, length).hex() == case["derive_key"],
        }
        passed = all(checks.values())
        failures += not passed
        cases.append({"input_len": case["input_len"], "passed": passed, "checks": checks})
    return {
        "procedure": "V1 official test vectors",
        "passed": failures == 0,
        "source": VECTOR_SOURCE,
        "vector_file_sha256": __import__("hashlib").sha256(path.read_bytes()).hexdigest(),
        "cases_total": len(cases),
        "cases_failed": failures,
        "checks_per_case": 7,
        "output_bytes_checked": len(data["cases"][0]["hash"]) // 2,
        "cases": cases,
        "interpretation": "Both the native engine and the independent reference implementation "
                          "reproduce the BLAKE3 team's published outputs.",
    }


# ── V2 ──────────────────────────────────────────────────────────────────────

def reference_cross_check(seed: int = 0xB1A3E3, random_cases: int = 24) -> Dict[str, Any]:
    rng = random.Random(seed)
    boundary = [0, 1, 63, 64, 65, 1023, 1024, 1025, 2047, 2048, 2049, 4096, 8193, 65537]
    lengths = boundary + [rng.randrange(0, 200_000) for _ in range(random_cases)]
    failures = []
    for length in lengths:
        payload = rng.randbytes(length)
        native = blake3.blake3(payload).hexdigest()
        reference = reference_hash(payload).hex()
        if native != reference:
            failures.append(length)
    return {
        "procedure": "V2 independent cross-implementation check",
        "passed": not failures,
        "inputs_tested": len(lengths),
        "lengths": lengths,
        "failures": failures,
        "seed": seed,
        "interpretation": "Native extension and pure-Python reference agree on every input.",
    }


# ── V3 ──────────────────────────────────────────────────────────────────────

def configuration_consistency(
    path: Optional[os.PathLike[str] | str] = None,
    *,
    synthetic_size: int = SMALL_FILE_LIMIT + 3 * MIB + 17,
    progress: ProgressCallback = None,
    max_file_bytes: int = CONSISTENCY_MAX_FILE_BYTES,
) -> Dict[str, Any]:
    """Hash one input every supported way and require a single digest.

    About forty full passes are needed, so a selected file larger than
    ``max_file_bytes`` is checked on a copy of its first CONSISTENCY_SAMPLE_BYTES
    (which still crosses the multithreading and memory-mapping thresholds).
    """
    temporary: Optional[tempfile.TemporaryDirectory] = None
    source_label = None
    if path is None:
        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name) / "consistency_input.bin"
        rng = random.Random(0xC0451)
        Path(path).write_bytes(rng.randbytes(synthetic_size))
        source_label = "synthetic %d bytes" % synthetic_size
    elif Path(path).stat().st_size > max_file_bytes:
        original = Path(path)
        temporary = tempfile.TemporaryDirectory()
        sample = Path(temporary.name) / "consistency_sample.bin"
        with open(original, "rb") as reader, open(sample, "wb") as writer:
            remaining = CONSISTENCY_SAMPLE_BYTES
            while remaining:
                block = reader.read(min(8 * MIB, remaining))
                if not block:
                    break
                writer.write(block)
                remaining -= len(block)
        source_label = "first %d MiB of %s (sample: the full file is too large for ~40 passes)" % (
            CONSISTENCY_SAMPLE_BYTES // MIB, original)
        path = sample
    file_path = Path(path)
    size = file_path.stat().st_size
    try:
        expected = hash_file(file_path, threads=1, allow_mmap=False).digest
        observations: List[Dict[str, Any]] = []

        def observe(label: str, digest: str) -> None:
            observations.append({"variant": label, "digest": digest, "matches": digest == expected})

        buffers = [64 * 1024, 256 * 1024, 512 * 1024, 1 * MIB, 2 * MIB, 8 * MIB, 16 * MIB]
        thread_counts = sorted({1, 2, physical_cpu_count(), logical_cpu_count()})
        steps = len(buffers) * len(thread_counts) + 14
        done = 0
        for buffer in buffers:
            for threads in thread_counts:
                hasher = blake3.blake3(max_threads=threads)
                view = memoryview(bytearray(buffer))
                with open(file_path, "rb", buffering=0) as source:
                    while True:
                        count = source.readinto(view)
                        if not count:
                            break
                        hasher.update(view[:count])
                view.release()
                observe("stream buffer=%d KiB threads=%d" % (buffer // 1024, threads), hasher.hexdigest())
                done += 1
                if progress:
                    progress("Consistency: buffer %d KiB × %d threads" % (buffer // 1024, threads),
                             done / steps)
        for config in BLAKE3_CONFIGS:
            observe("configuration: " + config.label, hash_file_config(file_path, config).digest)
        observe("configuration: Optimized with mapping disabled (background-read fallback)",
                hash_file_config(file_path, "optimized", allow_mmap=False).digest)
        observe("mmap (engine default policy)", hash_file(file_path, allow_mmap=True).digest)
        if size <= 512 * MIB:
            data = file_path.read_bytes()
            observe("in-memory one-shot, 1 thread", blake3.blake3(data, max_threads=1).hexdigest())
            observe("in-memory one-shot, auto threads",
                    blake3.blake3(data, max_threads=blake3.blake3.AUTO).hexdigest())
            observe("stream API (hash_stream)",
                    hash_stream(io.BytesIO(data), len(data), collect_metrics=False).digest)
            for profile in STREAM_CONFIG_PROFILES:  # the Autopsy engine profiles (Table 8)
                observe("Autopsy stream profile " + profile,
                        hash_stream_profile(io.BytesIO(data), len(data), profile=profile,
                                            collect_metrics=False).digest)
            request = (json.dumps({"batch": 2, "requests": [
                {"size": len(data), "profile": "blake3_optimized"},
                {"size": len(data), "profile": "blake3_baseline"}]}).encode() + b"\n" + data + data)
            response = io.BytesIO()
            serve_forever(io.BytesIO(request), response)
            for line, label in zip(response.getvalue().splitlines(), ("C4", "C0")):
                observe("Autopsy batch request (%s profile)" % label, json.loads(line).get("digest", ""))
        if size < SMALL_FILE_LIMIT:
            observe("small-file worker (unbatched)", _small_file_worker(str(file_path))[0])
            observe("small-file worker (batched)", _small_batch_worker([str(file_path)])[0][0])
        if progress:
            progress("Consistency checks complete", 1.0)
        mismatches = [o["variant"] for o in observations if not o["matches"]]
        return {
            "procedure": "V3 configuration consistency",
            "passed": not mismatches,
            "input": source_label or str(file_path),
            "input_bytes": size,
            "expected_digest": expected,
            "variants_tested": len(observations),
            "mismatches": mismatches,
            "observations": observations,
            "interpretation": "Buffer size, thread count, I/O path and every studied optimization "
                              "change only performance, never the digest.",
        }
    finally:
        if temporary is not None:
            temporary.cleanup()


# ── Hash-behaviour tests of thesis Section 3.5 (Eq. 13–16) ──────────────────
# Every digest below is computed through the optimized engine's stream path
# (hash_stream_profile, profile "blake3_optimized": Table 7 buffer, physical-core
# threads at 32 MiB and above), so the tests observe the optimized
# implementation, not only the underlying library.

AVALANCHE_INPUTS = 1000          # random inputs, one bit flipped in each
AVALANCHE_INPUT_BYTES = 4096     # 4 BLAKE3 chunks, so the Merkle tree is exercised
DISTRIBUTION_DIGESTS = 10000     # digests of distinct random inputs
DISTRIBUTION_INPUT_BYTES = 64
REPETITIONS = 10                 # deterministic-output repetitions per input
LARGE_DETERMINISM_BYTES = SMALL_FILE_LIMIT + 8 * MIB + 3  # crosses the threading threshold
CHI_SQUARE_ALPHA = 0.05


def optimized_digest(data: bytes) -> bytes:
    """BLAKE3 digest of ``data`` computed by the optimized engine's stream path."""
    result = hash_stream_profile(io.BytesIO(data), len(data), profile="blake3_optimized",
                                 collect_metrics=False)
    if result.status != "ok":
        raise RuntimeError("optimized engine failed: %s" % result.error)
    return bytes.fromhex(result.digest)


def random_inputs(count: int, size: int, seed: int) -> List[bytes]:
    """Seeded, distinct random inputs (an 8-byte index prefix guarantees distinctness)."""
    rng = random.Random(seed)
    return [index.to_bytes(8, "little") + rng.randbytes(max(0, size - 8)) for index in range(count)]


def collision_test(digests: Sequence[bytes]) -> Dict[str, Any]:
    """Eq. 15: identical digests among the N digests of distinct inputs."""
    n = len(digests)
    pairs = n * (n - 1) // 2
    counts: Dict[bytes, int] = {}
    for digest in digests:
        counts[digest] = counts.get(digest, 0) + 1
    collisions = sum(c * (c - 1) // 2 for c in counts.values() if c > 1)
    return {
        "procedure": "H1 collision test",
        "passed": collisions == 0,
        "digests_compared": n,
        "pairs_compared": pairs,
        "collisions_found": collisions,
        "collision_rate": collisions / pairs if pairs else 0.0,
        "expected": "no collisions",
        "interpretation": "No two distinct inputs produced the same digest. With 2^256 possible "
                          "digests a collision is not expected before about 2^128 inputs, so "
                          "this does not establish collision resistance.",
    }


def avalanche_test(inputs: Sequence[bytes], seed: int = 0xA11A1A) -> Dict[str, Any]:
    """Eq. 13: flip one random bit in each input and compare the two digests."""
    rng = random.Random(seed)
    effects: List[float] = []
    distances: List[int] = []
    for data in inputs:
        if not data:
            continue
        original = optimized_digest(bytes(data))
        changed = bytearray(data)
        position = rng.randrange(len(changed) * 8)
        changed[position // 8] ^= 1 << (position % 8)
        flipped = optimized_digest(bytes(changed))
        distance = sum((a ^ b).bit_count() for a, b in zip(original, flipped))
        distances.append(distance)
        effects.append(distance / 256 * 100)  # Eq. 13
    if not effects:
        return {"procedure": "H2 avalanche effect test", "passed": False, "applicable": False,
                "error": "no non-empty inputs"}
    n = len(effects)
    mean = statistics.fmean(effects)
    sd = statistics.stdev(effects) if n > 1 else 0.0
    # Expected AE = 50 % with SD 100·√(256·¼)/256 = 3.125 % for an ideal hash.
    z = (mean - 50.0) / (3.125 / math.sqrt(n))
    return {
        "procedure": "H2 avalanche effect test",
        "passed": abs(z) < Z_CRITICAL,
        "applicable": True,
        "inputs": n,
        "input_bytes": len(inputs[0]),
        "seed": seed,
        "mean_avalanche_percent": round(mean, 4),
        "sd_avalanche_percent": round(sd, 4),
        "mean_changed_bits": round(statistics.fmean(distances), 3),
        "min_changed_bits": min(distances),
        "max_changed_bits": max(distances),
        "z_vs_50_percent": round(z, 3),
        "criterion": "average avalanche effect close to 50 % (|z| < 3.29 against 50 %, "
                     "SD of an ideal hash = 3.125 %)",
        "interpretation": "A one-bit input change altered about half of the 256 output bits.",
    }


def distribution_test(digests: Sequence[bytes]) -> Dict[str, Any]:
    """Eq. 14: chi-square of the digest byte values against a uniform distribution."""
    observed = [0] * 256
    for digest in digests:
        for value in digest:
            observed[value] += 1
    total = sum(observed)
    expected = total / 256.0
    chi_square = sum((o - expected) ** 2 / expected for o in observed) if expected else 0.0
    p_value = chi_square_sf(chi_square, 255)
    return {
        "procedure": "H3 hash distribution test",
        "passed": p_value >= CHI_SQUARE_ALPHA,
        "digests": len(digests),
        "bytes_counted": total,
        "expected_per_byte_value": expected,
        "chi_square": round(chi_square, 3),
        "degrees_of_freedom": 255,
        "p_value": p_value,
        "criterion": "chi-square not significant at the 0.05 level",
        "min_observed": min(observed),
        "max_observed": max(observed),
        "interpretation": "Digest byte values are consistent with a uniform distribution.",
    }


def deterministic_test(inputs: Sequence[bytes], repetitions: int = REPETITIONS) -> Dict[str, Any]:
    """Eq. 16: hash each input ``repetitions`` times; every repetition must be identical."""
    identical = total = 0
    differing: List[int] = []
    for index, data in enumerate(inputs):
        first = optimized_digest(data)
        identical += 1
        total += 1
        for _ in range(repetitions - 1):
            total += 1
            if optimized_digest(data) == first:
                identical += 1
            elif index not in differing:
                differing.append(index)
    determinism = 100.0 * identical / total if total else 0.0
    return {
        "procedure": "H4 deterministic output test",
        "passed": identical == total,
        "inputs": len(inputs),
        "repetitions_per_input": repetitions,
        "repetitions": total,
        "identical_repeated_digests": identical,
        "deterministic_percent": determinism,
        "largest_input_bytes": max((len(d) for d in inputs), default=0),
        "inputs_with_differences": differing,
        "interpretation": "Hashing the same input repeatedly always gives the same digest, "
                          "including inputs large enough to use multithreaded hashing.",
    }


# ── Orchestration ───────────────────────────────────────────────────────────

def run_validation(
    path: Optional[os.PathLike[str] | str] = None,
    *,
    avalanche_inputs: int = AVALANCHE_INPUTS,
    distribution_digests: int = DISTRIBUTION_DIGESTS,
    repetitions: int = REPETITIONS,
    progress: ProgressCallback = None,
) -> Dict[str, Any]:
    """Supporting correctness checks (V1–V3) and the hash-behaviour tests (H1–H4).

    ``path`` (optional) is used only by the configuration-consistency check V3;
    H1–H4 use seeded random inputs, as specified in Section 3.5.
    """
    def report(message: str, fraction: float) -> None:
        if progress:
            progress(message, fraction)

    started = time.perf_counter()
    report("V1 official test vectors…", 0.02)
    vectors = official_test_vectors()
    report("V2 cross-implementation check…", 0.10)
    cross = reference_cross_check()
    report("V3 configuration consistency…", 0.20)
    consistency = configuration_consistency(
        path, progress=lambda m, f: report(m, 0.20 + 0.3 * f))
    report("H1/H3 hashing %d distinct random inputs…" % distribution_digests, 0.52)
    digests = [optimized_digest(data) for data in
               random_inputs(distribution_digests, DISTRIBUTION_INPUT_BYTES, seed=0xD157)]
    collisions = collision_test(digests)
    distribution = distribution_test(digests)
    report("H2 avalanche effect (%d inputs)…" % avalanche_inputs, 0.66)
    avalanche_set = random_inputs(avalanche_inputs, AVALANCHE_INPUT_BYTES, seed=0xA7A1)
    avalanche = avalanche_test(avalanche_set)
    report("H4 deterministic output (×%d)…" % repetitions, 0.80)
    large = random.Random(0xB16).randbytes(LARGE_DETERMINISM_BYTES)
    determinism = deterministic_test(list(avalanche_set) + [large], repetitions=repetitions)
    report("Verification complete", 1.0)
    procedures = [vectors, cross, consistency, collisions, avalanche, distribution, determinism]
    return {
        "schema_version": 3,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "passed": all(p.get("passed") for p in procedures if p.get("applicable", True)),
        "input": str(path) if path else "synthetic",
        "hash_behaviour_inputs": {
            "collision_and_distribution": "%d distinct random inputs of %d bytes (seeded)"
                                          % (distribution_digests, DISTRIBUTION_INPUT_BYTES),
            "avalanche": "%d random inputs of %d bytes, one random bit flipped in each (seeded)"
                         % (avalanche_inputs, AVALANCHE_INPUT_BYTES),
            "deterministic": "the %d avalanche inputs plus one %d-byte input, each hashed %d times"
                             % (avalanche_inputs, LARGE_DETERMINISM_BYTES, repetitions),
            "engine_path": "optimized engine stream path (profile blake3_optimized)",
        },
        "engine_self_test": self_test(),
        "procedures": procedures,
        "limitations": LIMITATIONS,
        "duration_seconds": round(time.perf_counter() - started, 2),
    }


# Backward-compatible wrapper used by older callers/tests.
def deterministic_correctness(seed: int = 0xB1A3E3) -> Dict[str, Any]:
    rng = random.Random(seed)
    failures = []
    for size in [0, 1, 63, 64, 1023, 1024, 1025, 2048, 8192, 65537, 1_048_577]:
        payload = rng.randbytes(size)
        reference = blake3.blake3(payload, max_threads=1).hexdigest()
        first = hash_stream(io.BytesIO(payload), size, threads=1, collect_metrics=False)
        second = hash_stream(io.BytesIO(payload), size, threads=physical_cpu_count(),
                             collect_metrics=False)
        if not (first.digest == reference == second.digest):
            failures.append(size)
    return {"passed": not failures, "failures": failures}


def main(argv: Optional[Sequence[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("path", nargs="?", help="optional file for the consistency check (V3)")
    parser.add_argument("--avalanche-inputs", type=int, default=AVALANCHE_INPUTS)
    parser.add_argument("--distribution-digests", type=int, default=DISTRIBUTION_DIGESTS)
    parser.add_argument("--repetitions", type=int, default=REPETITIONS)
    parser.add_argument("--output", help="write the JSON report here")
    args = parser.parse_args(argv)
    result = run_validation(args.path, avalanche_inputs=args.avalanche_inputs,
                            distribution_digests=args.distribution_digests,
                            repetitions=args.repetitions)
    encoded = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    for procedure in result["procedures"]:
        print("%-45s %s" % (procedure["procedure"], "PASS" if procedure.get("passed") else "FAIL"))
    print("Limitations:", result["limitations"])
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
