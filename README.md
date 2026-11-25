# Optimized BLAKE3 — Forensic Hashing Toolkit

> **Thesis:** *Performance Optimization for BLAKE3 for Multi-Format File Hashing in Digital Forensic Investigations*
>
> An optimization **for** BLAKE3, not **of** BLAKE3: the way files are read, grouped and scheduled is
> optimized; the BLAKE3 algorithm, its tree structure and constants are unchanged.

The code implements thesis Chapter 3:

| Part | Files | Thesis |
|---|---|---|
| Optimized BLAKE3 hashing engine | `dev/optimized_blake3.py` → `optimized_blake3_hasher.exe` | Section 3.4, Figure 3, Tables 6–7 |
| Autopsy ingest module (evaluated system) | `autopsy_plugin/BLAKE3_Autopsy_Module/` | Sections 3.4–3.5, Figure 4, Table 8 |
| Statistics and trial analysis | `dev/benchmark_blake3.py` | Section 3.5, Equations 1–19 |
| Hash-behaviour tests | `dev/blake3_validation.py` | Section 3.5 (collision, avalanche, distribution, deterministic) |
| Standalone application (supplementary) | `main_app.py` | everyday hashing and in-app evaluation |

## Optimization policy (Table 7)

| Input size | Reusable buffer | Native BLAKE3 threads | Autopsy transfer |
|---|---:|---|---|
| below 512 KiB | 64 KiB | one | eligible for batching |
| 512 KiB – below 4 MiB | 256 KiB | one | eligible for batching |
| 4 MiB – below 32 MiB | 512 KiB | one | eligible for batching |
| 32 MiB – below 128 MiB | 2 MiB | detected physical cores | individual |
| 128 MiB – below 1 GiB | 8 MiB | detected physical cores | individual |
| 1 GiB and above | 16 MiB | detected physical cores | individual |

Batches hold up to 32 files below 32 MiB; each file keeps its own hasher and digest. The engine
allocates one buffer per size and refills it with `readinto()` through a `memoryview`. Native SIMD
dispatch is identical in every configuration and is not a studied technique.

## Configurations (Table 8)

Selected per ingest job in the module's settings panel (or with `BLAKE3_CONFIGURATION`):

| Code | Input buffer | Small-file batching | Native threads |
|---|---|---|---|
| C0 Baseline BLAKE3 | fixed 1 MiB | no | one |
| C1 Buffer sizing only | adaptive (Table 7) | no | one |
| C2 Batching only | fixed 1 MiB | files below 32 MiB | one |
| C3 Threading only | fixed 1 MiB | no | physical cores at 32 MiB and above |
| C4 Full optimized implementation | adaptive (Table 7) | files below 32 MiB | physical cores at 32 MiB and above |
| R1 MD5 | fixed 1 MiB | no | n/a |
| R2 SHA-256 | fixed 1 MiB | no | n/a |

## Running the Autopsy trials

1. Build the engine (Python 3.14, blake3 1.0.8) and install the module — see `dev/README.md`.
2. Set Autopsy's file ingest threads to a fixed value (Tools → Options → Ingest) and keep it for
   every run; the report and the trials CSV record it.
3. For each disk image and each trial block 1–30, run every configuration once in a rotated
   order: add the image as a data source, enable **Optimized BLAKE3 Hasher**, choose the
   configuration and trial block in its settings, and start ingest.
4. Each run appends one row to `%USERPROFILE%\BLAKE3_Trials\autopsy_trials.csv`
   (`BLAKE3_TRIALS_CSV` overrides the path) and writes an HTML/JSON report to the case Reports folder.
5. Analyze:

```bash
cd dev
python benchmark_blake3.py autopsy %USERPROFILE%\BLAKE3_Trials\autopsy_trials.csv --output ../results
```

The analysis reports, per disk image and separately for the readable files and the complete
evidence source: mean, SD, 95 % CI (t critical value) and CV of each configuration (Eq. 7–10);
C1–C4 against C0 on trials paired by block, with Shapiro–Wilk on the paired differences, then a
paired t-test (normal) or Wilcoxon signed-rank test, Holm correction over the four comparisons,
speedup and percent reduction (Eq. 3–4), effect size d (Eq. 18) and the parallel portion implied
by Amdahl's Law (Eq. 17). Runs with trial block 0 are excluded.

Verification passes (baseline BLAKE3, MD5, SHA-256 in separate full passes after hashing) give
digest agreement (Eq. 11); completeness (Eq. 12) compares the files reported with the readable
files of the data source in the case database. Turning the passes off in the settings shortens
timing trials; they never change the timed hashing pass.

## Hash-behaviour tests

```bash
cd dev
python blake3_validation.py --output verification.json
```

V1–V3 are supporting correctness checks (official vectors, an independent pure-Python BLAKE3,
consistency across every buffer, thread count, configuration and engine profile). H1–H4 are the
Section 3.5 tests, computed through the optimized engine: collisions among 10,000 digests (Eq. 15),
avalanche over 1,000 random inputs with one bit flipped (Eq. 13), chi-square of the digest byte
values (Eq. 14) and ten repetitions per input (Eq. 16). They are supporting observations, not a
cryptographic audit.

## Standalone application (supplementary)

```bash
pip install -r requirements.txt
python main_app.py
```

Hash Files (with `.b3` hash lists and re-checking), File Analysis, System Overview and Methodology
are always available. Evaluation mode adds Technique Evaluation (C0, C1, C3, C4 on local files
with R1/R2), Batch Processing (batching and parallel dispatch of many small local files),
Correctness Verification (V1–V3, H1–H4) and Test Dataset. Both evaluation pages use the
Section 3.5 statistics. For local files of 32 MiB and above on SSD/NVMe storage the app's
adaptive buffer is a memory map (Section 3.4: "the mmap module provides memory-mapped access to
large local files"); on HDDs, network shares, or when mapping fails it reads with the Table 7
buffer. Peak memory of mapped runs includes the mapped file pages (shared, reclaimable file
cache), not only allocated memory.

## Command line

```bash
cd dev
python optimized_blake3.py FILE_OR_FOLDER [...] [--extra blake3_standard sha256] [--save ../results]
python optimized_blake3.py --check ../results/hashes_YYYYMMDD_HHMMSS.b3
python optimized_blake3.py --self-test
python benchmark_blake3.py autopsy TRIALS_CSV --output ../results
python benchmark_blake3.py large FILE [FILE ...] --trials 30 --output ../results
python benchmark_blake3.py small FOLDER --trials 30 --output ../results
python blake3_validation.py [optional-file] --output verification.json
python dataset_tool.py manifest ../digital_evidence_dataset
python -m pytest -q tests
```

## Dataset guidance

Place evidence in `digital_evidence_dataset/` (git-ignored) and record its source in
`digital_evidence_dataset/sources.json`. The disk images of Table 2 should together cover many
small files (batching), a few very large files (multithreading) and a realistic mix of documents,
images, audio, video, executables and archives. Public sources include NIST CFReDS and Digital
Corpora. An E01 container hashed as a stored file is not the acquisition hash recorded inside it.

All tool names and the thesis title are set in one place (`TOOL_SHORT_NAME`, `TOOL_SUBTITLE`,
`THESIS_TITLE` near the top of `dev/optimized_blake3.py`).
