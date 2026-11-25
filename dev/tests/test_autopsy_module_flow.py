"""End-to-end test of the Autopsy ingest module under CPython.

The Jython module is executed with stand-in Java/Autopsy classes, while the
engine is the real ``optimized_blake3.py --server`` process speaking the real
stream protocol. This exercises, for every Table 8 configuration: startup
probes, per-file and batched hashing, transfer buffers, verification passes,
evidence-source hashing, artifact queueing, the HTML/JSON report and the
trials CSV, without a live Autopsy installation.
"""
import builtins
import csv
import hashlib
import os
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

import blake3

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "autopsy_plugin" / "BLAKE3_Autopsy_Module" / "blake3_ingest_module.py"
# BLAKE3_TEST_ENGINE=<path to optimized_blake3_hasher.exe> runs the same checks
# against the packaged engine instead of the Python source.
ENGINE = Path(os.environ.get("BLAKE3_TEST_ENGINE") or ROOT / "dev" / "optimized_blake3.py")
MIB = 1024 * 1024


# ── stand-ins for the Java / Autopsy classes the module imports ─────────────

class _Stream:
    def __init__(self, raw):
        self.raw = raw

    def write(self, data, offset=0, length=None):
        if isinstance(data, str):
            data = data.encode("ascii")
        view = memoryview(data)
        self.raw.write(view[offset:offset + length] if length is not None else view)

    def flush(self):
        self.raw.flush()

    def close(self):
        try:
            self.raw.close()
        except Exception:
            pass


class _Process:
    def __init__(self, command):
        self.popen = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def getOutputStream(self):
        return _Stream(self.popen.stdin)

    def getInputStream(self):
        return self.popen.stdout

    def isAlive(self):
        return self.popen.poll() is None

    def destroy(self):
        try:
            self.popen.kill()
            self.popen.wait(timeout=10)
        except Exception:
            pass
        for pipe in (self.popen.stdin, self.popen.stdout):
            try:
                pipe.close()
            except Exception:
                pass


class ProcessBuilder:
    def __init__(self, command):
        command = list(command)
        if command[0].endswith(".py"):
            command = [sys.executable] + command
        self.command = command

    def redirectErrorStream(self, _value):
        pass

    def start(self):
        return _Process(self.command)


class InputStreamReader:
    def __init__(self, stream):
        self.stream = stream


class BufferedReader:
    def __init__(self, reader):
        self.stream = reader.stream

    def readLine(self):
        line = self.stream.readline()
        return line.decode("utf-8").rstrip("\r\n") if line else None

    def close(self):
        pass


class FileInputStream:
    def __init__(self, path):
        self.handle = open(path, "rb")

    def read(self, buffer):
        data = self.handle.read(len(buffer))
        if not data:
            return -1
        buffer[:len(data)] = data
        return len(data)

    def close(self):
        self.handle.close()


class MessageDigest:
    @staticmethod
    def getInstance(_name):
        digest = types.SimpleNamespace(h=hashlib.sha256())
        digest.update = lambda buffer, offset, count: digest.h.update(bytes(buffer[offset:offset + count]))
        digest.digest = lambda: list(digest.h.digest())
        return digest


class JString(str):
    def getBytes(self, _encoding):
        return self.encode("ascii")


class GenericIngestModuleJobSettings:
    def __init__(self):
        self.values = {}

    def getSetting(self, key):
        return self.values.get(key)

    def setSetting(self, key, value):
        self.values[key] = value


class _Enum:
    def __init__(self, value):
        self.value = value

    def getValue(self):
        return self.value

    def getFileType(self):
        return self.value


TskData = types.SimpleNamespace(
    TSK_DB_FILES_TYPE_ENUM=types.SimpleNamespace(
        UNALLOC_BLOCKS=_Enum(4), UNUSED_BLOCKS=_Enum(5), FS=_Enum(0)),
    TSK_FS_META_TYPE_ENUM=types.SimpleNamespace(TSK_FS_META_TYPE_DIR=_Enum(2)),
)


class IngestModuleException(Exception):
    pass


class _Messages:
    posted = []


def _module(name, **attributes):
    module = types.ModuleType(name)
    module.__dict__.update(attributes)
    return module


def install_stubs(world):
    swing = dict(JOptionPane=object, SwingUtilities=types.SimpleNamespace(invokeLater=lambda f: None),
                 BoxLayout=object, JCheckBox=object, JComboBox=object, JLabel=object,
                 JSpinner=object, SpinnerNumberModel=object)
    ingest = dict(
        DataSourceIngestModule=object, FileIngestModule=object,
        GenericIngestModuleJobSettings=GenericIngestModuleJobSettings,
        IngestMessage=types.SimpleNamespace(
            MessageType=types.SimpleNamespace(ERROR="error", WARNING="warning", INFO="info"),
            createMessage=lambda *args: args),
        IngestModule=types.SimpleNamespace(
            ProcessResult=types.SimpleNamespace(OK="OK"),
            IngestModuleException=IngestModuleException),
        IngestModuleFactoryAdapter=object,
        IngestModuleIngestJobSettingsPanel=object,
        IngestManager=types.SimpleNamespace(
            IngestJobEvent=types.SimpleNamespace(),
            getInstance=lambda: types.SimpleNamespace(
                addIngestJobEventListener=lambda listener: None,
                removeIngestJobEventListener=lambda listener: None)),
        IngestServices=types.SimpleNamespace(getInstance=lambda: types.SimpleNamespace(
            postMessage=_Messages.posted.append)),
    )
    modules = {
        "java": _module("java"), "java.io": _module("java.io", BufferedReader=BufferedReader,
                                                     File=lambda p: p, FileInputStream=FileInputStream,
                                                     InputStreamReader=InputStreamReader),
        "java.awt": _module("java.awt", Desktop=object),
        "java.lang": _module("java.lang", ProcessBuilder=ProcessBuilder, String=JString,
                             System=types.SimpleNamespace(nanoTime=time.perf_counter_ns,
                                                          getProperty=lambda key: world["home"])),
        "java.security": _module("java.security", MessageDigest=MessageDigest),
        "java.util": _module("java.util", ArrayList=list, Vector=list),
        "java.beans": _module("java.beans", PropertyChangeListener=object),
        "jarray": _module("jarray", zeros=lambda n, _t: bytearray(n)),
        "javax": _module("javax"), "javax.swing": _module("javax.swing", **swing),
        "org": _module("org"), "org.sleuthkit": _module("org.sleuthkit"),
        "org.sleuthkit.autopsy": _module("org.sleuthkit.autopsy"),
        "org.sleuthkit.autopsy.casemodule": _module("org.sleuthkit.autopsy.casemodule",
                                                    Case=world["Case"]),
        "org.sleuthkit.autopsy.ingest": _module("org.sleuthkit.autopsy.ingest", **ingest),
        "org.sleuthkit.datamodel": _module("org.sleuthkit.datamodel",
                                           BlackboardAttribute=object, TskData=TskData),
    }
    sys.modules.update(modules)
    return list(modules)


def _binary_safe_open(path, mode="r", *args, **kwargs):
    # Jython 2.7 writes str to files opened in binary mode; CPython needs text mode.
    if "b" in mode and ("w" in mode or "a" in mode):
        return builtins.open(path, mode.replace("b", ""), encoding="utf-8", newline="")
    return builtins.open(path, mode, *args, **kwargs)


class FakeContent:
    def __init__(self, object_id, name, data, file_type=None, is_dir=False):
        self.object_id, self.name, self.data = object_id, name, data
        self.file_type = file_type or TskData.TSK_DB_FILES_TYPE_ENUM.FS
        self.is_dir = is_dir

    def read(self, buffer, offset, length):
        chunk = self.data[offset:offset + length]
        buffer[:len(chunk)] = chunk
        return len(chunk) if chunk else -1

    def getSize(self):
        return len(self.data)

    def getName(self):
        return self.name

    def getId(self):
        return self.object_id

    def isDir(self):
        return self.is_dir

    def getType(self):
        return self.file_type

    def getMd5Hash(self):
        return hashlib.md5(self.data).hexdigest()

    def getSha256Hash(self):
        return None


class AutopsyModuleFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        rng = __import__("random").Random(42)
        cls.files = [FakeContent(100 + i, "doc%02d.txt" % i, rng.randbytes(1000 + 997 * i))
                     for i in range(40)]
        cls.files.append(FakeContent(200, "video.mp4", rng.randbytes(33 * MIB + 5)))
        cls.files.append(FakeContent(201, "folder", b"", is_dir=True))
        cls.files.append(FakeContent(202, "Unalloc_1", rng.randbytes(500),
                                     file_type=TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS))
        cls.readable = [f for f in cls.files if not f.is_dir
                        and f.file_type is TskData.TSK_DB_FILES_TYPE_ENUM.FS]
        cls.image = FakeContent(7, "evidence.dd", rng.randbytes(3 * MIB + 11))
        cls.reports = root / "reports"
        cls.reports.mkdir()
        sleuthkit = types.SimpleNamespace(
            getBlackboard=lambda: object(),
            countFilesWhere=lambda where: len(cls.readable),
            getAbstractFileById=lambda object_id: next(
                (f for f in cls.files if f.object_id == object_id), None))
        case = types.SimpleNamespace(getSleuthkitCase=lambda: sleuthkit,
                                     getReportDirectory=lambda: str(cls.reports),
                                     getName=lambda: "unit-test-case", getExaminer=lambda: "tester",
                                     addReport=lambda *args: None)
        world = {"home": str(root), "Case": types.SimpleNamespace(getCurrentCase=lambda: case)}
        cls.stub_names = install_stubs(world)
        os.environ["BLAKE3_ENGINE_PATH"] = str(ENGINE)
        cls.csv_path = root / "trials.csv"
        os.environ["BLAKE3_TRIALS_CSV"] = str(cls.csv_path)
        cls.plugin = {"__name__": "blake3_ingest_module", "__file__": str(PLUGIN),
                      "open": _binary_safe_open}
        exec(compile(PLUGIN.read_text(encoding="utf-8"), str(PLUGIN), "exec"), cls.plugin)
        cls.runs = {}
        for block, code in enumerate(("C0", "C1", "C2", "C3", "C4", "R1", "R2"), 1):
            cls.runs[code] = cls.run_ingest(code, job_id=block, trial_block=block)

    @classmethod
    def tearDownClass(cls):
        for name in cls.stub_names:
            sys.modules.pop(name, None)
        os.environ.pop("BLAKE3_ENGINE_PATH", None)
        os.environ.pop("BLAKE3_TRIALS_CSV", None)
        cls.temp.cleanup()

    @classmethod
    def run_ingest(cls, code, job_id, trial_block, verification=True):
        plugin = cls.plugin
        factory = plugin["BLAKE3IngestModuleFactory"]()
        settings = factory.getDefaultIngestJobSettings()
        settings.setSetting("configuration", code)
        settings.setSetting("trial_block", str(trial_block))
        settings.setSetting("verification_passes", "true" if verification else "false")
        context = types.SimpleNamespace(getJobId=lambda: job_id, getDataSource=lambda: cls.image,
                                        isJobCancelled=lambda: False)
        progress = types.SimpleNamespace(switchToDeterminate=lambda n: None, progress=lambda n: None)
        file_module = factory.createFileIngestModule(settings)
        source_module = factory.createDataSourceIngestModule(settings)
        file_module.startUp(context)
        source_module.startUp(context)
        for content in cls.files:
            file_module.process(content)
        file_module.shutDown()
        source_module.process(cls.image, progress)
        source_module.shutDown()
        listener = plugin["_BLAKE3ReportListener"](job_id, cls.image.getId())
        with plugin["_JOBS_LOCK"]:
            plugin["_job"](job_id)["finalizing_sources"].append(cls.image.getId())
        listener._finalize()
        return plugin["_job"](job_id)

    def file_rows(self, code):
        return [r for r in self.runs[code]["rows"] if r.get("source_kind") == "File"]

    def evidence_row(self, code):
        return next(r for r in self.runs[code]["rows"] if r.get("source_kind") == "Evidence source")

    # ── behaviour that Chapter 3 states ────────────────────────────────────

    def test_every_readable_file_hashed_with_correct_digest(self):
        expected = {f.name: blake3.blake3(f.data).hexdigest() for f in self.readable}
        for code in ("C0", "C1", "C2", "C3", "C4"):
            rows = {r["name"]: r for r in self.file_rows(code) if r["status"] == "ok"}
            self.assertEqual(set(rows), set(expected), code)
            for name, digest in expected.items():
                self.assertEqual(rows[name]["digest"], digest, (code, name))
                self.assertTrue(rows[name]["baseline_blake3_matches"], (code, name))

    def test_reference_runs_use_md5_and_sha256(self):
        md5 = {r["name"]: r["digest"] for r in self.file_rows("R1") if r["status"] == "ok"}
        sha = {r["name"]: r["digest"] for r in self.file_rows("R2") if r["status"] == "ok"}
        for content in self.readable:
            self.assertEqual(md5[content.name], hashlib.md5(content.data).hexdigest())
            self.assertEqual(sha[content.name], hashlib.sha256(content.data).hexdigest())
        self.assertEqual(self.runs["R1"]["pending_artifacts"], [])  # no BLAKE3 artifacts for R runs

    def test_directories_and_unallocated_blocks_are_skipped_with_reason(self):
        skipped = {r["name"]: r for r in self.file_rows("C4") if r["status"] == "skipped"}
        self.assertEqual(set(skipped), {"folder", "Unalloc_1"})
        self.assertTrue(all(r.get("reason") for r in skipped.values()))

    def test_batching_only_in_c2_and_c4_and_only_below_32_mib(self):
        for code in ("C0", "C1", "C2", "C3", "C4", "R1", "R2"):
            rows = [r for r in self.file_rows(code) if r["status"] == "ok"]
            small = [r for r in rows if r["size_bytes"] < 32 * MIB]
            large = [r for r in rows if r["size_bytes"] >= 32 * MIB]
            batched = code in ("C2", "C4")
            self.assertTrue(all(bool(r.get("batch_mode")) == batched for r in small), code)
            self.assertFalse(any(r.get("batch_mode") for r in large), code)
            if batched:
                self.assertTrue(all(r["batch_item_count"] <= 32 for r in small))

    def test_buffers_and_threads_follow_tables_7_and_8(self):
        cores = os.cpu_count()
        import psutil
        cores = psutil.cpu_count(logical=False) or cores
        for code in ("C0", "C1", "C2", "C3", "C4"):
            for row in (r for r in self.file_rows(code) if r["status"] == "ok"):
                size = row["size_bytes"]
                adaptive = code in ("C1", "C4")
                expected_buffer = self.plugin["_adaptive_buffer"](size) if adaptive else MIB
                self.assertEqual(row["chunk_size"], expected_buffer, (code, row["name"]))
                self.assertEqual(row["transfer_buffer"], expected_buffer, (code, row["name"]))
                threaded = code in ("C3", "C4") and size >= 32 * MIB
                self.assertEqual(row["threads_used"], cores if threaded else 1, (code, row["name"]))

    def test_evidence_source_warm_up_then_timed_pass_with_verification(self):
        for code in ("C0", "C4"):
            row = self.evidence_row(code)
            self.assertEqual(row["status"], "ok")
            self.assertTrue(row["warmup_digest_matches"])
            self.assertEqual(row["digest"], blake3.blake3(self.image.data).hexdigest())
            self.assertTrue(row["baseline_blake3_matches"])
            self.assertEqual(row["sha256_digest"], hashlib.sha256(self.image.data).hexdigest())

    def test_verification_passes_cover_baseline_md5_sha256_not_sha1(self):
        row = next(r for r in self.file_rows("C4") if r["status"] == "ok")
        for prefix in ("baseline_blake3", "md5", "sha256"):
            self.assertEqual(row[prefix + "_status"], "ok")
        self.assertNotIn("sha1_status", row)
        self.assertTrue(row["md5_matches_autopsy"])  # Autopsy-stored MD5 comparison

    def test_trials_csv_one_row_per_run_with_completeness_and_agreement(self):
        with open(self.csv_path, newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual([r["configuration"] for r in rows], ["C0", "C1", "C2", "C3", "C4", "R1", "R2"])
        self.assertEqual([r["trial_block"] for r in rows], [str(i) for i in range(1, 8)])
        for row in rows:
            self.assertEqual(row["files_hashed"], str(len(self.readable)))
            self.assertEqual(float(row["completeness_percent"]), 100.0)
            self.assertGreater(float(row["file_hashing_ms"]), 0)
            self.assertGreater(float(row["evidence_ms"]), 0)
            self.assertEqual(row["data_source"], "evidence.dd")
        for row in rows[:5]:
            self.assertEqual(float(row["digest_agreement_percent"]), 100.0)
        for row in rows[5:]:
            self.assertEqual(row["digest_agreement_percent"], "")

    def test_report_names_the_configuration_and_has_no_sha1(self):
        reports = sorted(self.reports.glob("BLAKE3_Hash_Report_*.html"))
        self.assertGreaterEqual(len(reports), 7)
        texts = [p.read_text(encoding="utf-8") for p in reports]
        for label in ("C0 Baseline BLAKE3", "C2 Batching only", "C4 Full optimized implementation",
                      "R1 MD5 (reference)"):
            self.assertTrue(any(label in text for text in texts), label)
        for text in texts:
            self.assertNotIn("SHA-1", text)
            self.assertIn("Report completeness (Eq. 12)", text)

    def test_trials_csv_feeds_the_statistical_analysis(self):
        import benchmark_blake3
        rows = benchmark_blake3.read_autopsy_trials(self.csv_path)
        analysis = benchmark_blake3.analyze_autopsy_trials(rows)
        scope = analysis["data_sources"][0]["scopes"][0]
        self.assertEqual(set(scope["configurations"]), {"C0", "C1", "C2", "C3", "C4", "R1", "R2"})
        self.assertTrue(any("fewer than 3 trial blocks" in w for w in analysis["warnings"]))


if __name__ == "__main__":
    unittest.main()
