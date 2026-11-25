# Optimized BLAKE3 engine and Autopsy ingest module

Implements thesis Chapter 3, Sections 3.4–3.5.

## Components

| File | Role |
|---|---|
| `optimized_blake3.py` | Hashing engine (Figure 3). `--server` is the persistent data stream used by Autopsy. |
| `../autopsy_plugin/BLAKE3_Autopsy_Module/blake3_ingest_module.py` | Jython 2.7 file + data source ingest module (Figure 4). |
| `../autopsy_plugin/BLAKE3_Autopsy_Module/optimized_blake3_hasher.exe` | Packaged engine (PyInstaller one-file build of `optimized_blake3.py`). |
| `benchmark_blake3.py` | Equations 1–19, the Section 3.5 statistics, and `autopsy` trial analysis. |
| `blake3_validation.py` | V1–V3 correctness checks and H1–H4 hash-behaviour tests. |
| `build_sidecar.ps1` | Builds and self-tests the engine executable. |
| `tests/` | Unit tests, plus `test_autopsy_module_flow.py`, which runs the ingest module under CPython with stand-in Autopsy classes against the real engine. |

## Engine stream protocol

```
{"size": N, "profile": P}\n<N bytes>
{"batch": M, "requests": [{"size": N0, "profile": P0}, ...]}\n<N0 + N1 + ... bytes>
```

One JSON result line per file, in request order (digest, status, elapsed time, throughput, CPU
utilization as the mean of 10 ms psutil samples with their count, peak RSS, threads, buffer size,
I/O strategy). Profiles: `blake3_baseline` (C0, C2), `blake3_buffer_only` (C1),
`blake3_threads_only` (C3), `blake3_optimized` (C4), `md5` (R1), `sha256` (R2), `sha1`. An
unknown profile's bytes are consumed and an error is returned, so the stream stays synchronized.

## Ingest module behaviour

- **Startup** (each module instance): start the engine once; check the empty-input BLAKE3 test
  vector; send a batch probe; probe every engine profile the job needs; stop the job if a check
  fails. A broken stream restarts the engine and repeats the check.
- **Settings panel:** configuration C0–C4 / R1 / R2 (Table 8), trial block (0 = not a measured
  trial), and whether to run the verification passes. Environment fallbacks:
  `BLAKE3_CONFIGURATION`, `BLAKE3_TRIAL_BLOCK`, `BLAKE3_VERIFICATION_PASSES`.
- **Files:** directories and unallocated/unused space blocks are recorded as SKIPPED with a
  reason. C2 and C4 collect up to 32 files below 32 MiB per ingest thread and send them in one
  request (a partial batch is sent when the thread finishes); everything else is one request per
  file. Bytes are read from Autopsy into a buffer of the configured size (Table 7 or 1 MiB) and
  written straight to the engine. Every result is checked for the exact byte count and a digest
  of the right length. Batch time is divided among the batch's files by size (BATCH-EST).
- **Verification passes** (optional, after hashing): baseline BLAKE3, then MD5, then SHA-256, each
  a separate full pass with a fixed 1 MiB buffer. A BLAKE3 configuration whose digest differs from
  baseline BLAKE3 is marked as an error. MD5/SHA-256 are compared with hashes stored by Autopsy
  when available.
- **Evidence source:** one untimed warm-up pass, then the timed pass (digests must match), then
  the verification passes.
- **Results:** BLAKE3 Hash (Optimized) artifacts are posted after the data source analysis
  completes (R1/R2 runs post none). The HTML/JSON report goes to the case Reports folder and is
  registered in Autopsy; one row per run is appended to the trials CSV
  (`%USERPROFILE%\BLAKE3_Trials\autopsy_trials.csv`, or `BLAKE3_TRIALS_CSV`), with completeness
  (Eq. 12), digest agreement (Eq. 11), file and evidence times, throughput, run CPU (Eq. 5) and
  peak RSS.

## Build and install

```powershell
.\build_sidecar.ps1 -Python C:\path\to\python.exe   # Python 3.14; installs blake3==1.0.8, psutil==7.2.2
Copy-Item .\dist\optimized_blake3_hasher.exe ..\autopsy_plugin\BLAKE3_Autopsy_Module\
```

The build script self-tests the executable. To test the packaged engine with the full module flow:

```powershell
$env:BLAKE3_TEST_ENGINE = "..\autopsy_plugin\BLAKE3_Autopsy_Module\optimized_blake3_hasher.exe"
python -m pytest -q tests\test_autopsy_module_flow.py
```

Install in Autopsy: Tools → Python Plugins, copy the `BLAKE3_Autopsy_Module` folder (module,
exe, logo) into the Python modules directory, restart Autopsy, and enable **Optimized BLAKE3
Hasher** in the ingest module list. Record the engine SHA-256 shown in the report.

## Notes

- Autopsy reads evidence through virtual content streams, so the Autopsy path always uses the
  buffered stream; memory mapping applies only to local files in the standalone application.
- Keep Autopsy's file ingest thread count fixed across trials; each ingest thread runs its own
  engine, and threaded configurations use all physical cores per large file.
- Sampled verification (`BLAKE3_COMPARE_EVERY_FILE=0`, with `BLAKE3_COMPARISON_SAMPLE_LIMIT`,
  `BLAKE3_INTEGRITY_SAMPLE_LIMIT`, `BLAKE3_PERFORMANCE_MIN_BYTES`) is available for very large
  cases; the default verifies every file, as in Section 3.5.
- Artifacts are queued during ingest and posted after the matching data-source-analysis-completed
  event, which avoids an Autopsy 4.22.1 lock cycle between `newArtifact()` and image import.
