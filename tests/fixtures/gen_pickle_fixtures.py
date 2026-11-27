"""Генератор фикстур для pickle-сканера (детерминированный).

Запуск: python -m tests.fixtures.gen_pickle_fixtures
Фикстуры пишутся в tests/fixtures/pickle/ и коммитятся в git.

Детерминизм:
- ZIP: фиксированный date_time, ZIP_STORED, стабильный порядок
- TAR: фиксированный mtime/uid/gid/uname/gname
- TAR.GZ: gzip с фиксированным mtime
Иначе git видит M на бинарях при каждом запуске (timestamp).
"""
from __future__ import annotations

import gzip
import io
import pickle
import tarfile
import zipfile
from pathlib import Path

OUT = Path(__file__).parent / "pickle"
OUT.mkdir(parents=True, exist_ok=True)

FIXED_ZIP_DATE = (2024, 1, 1, 0, 0, 0)
FIXED_MTIME = 1704067200  # 2024-01-01 00:00:00 UTC


def _evil_reduce():
    class Evil:
        def __reduce__(self):
            import os
            return (os.system, ("echo pwned",))
    return Evil()


def write(name: str, data: bytes) -> None:
    (OUT / name).write_bytes(data)


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    """Детерминированный ZIP: фиксированный timestamp, ZIP_STORED, порядок как в dict."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_DATE)
            info.compress_type = zipfile.ZIP_STORED
            zf.writestr(info, data)
    return buf.getvalue()


def _tarinfo(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mtime = FIXED_MTIME
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mode = 0o644
    return info


def _tar_bytes(entries: dict[str, bytes]) -> bytes:
    """Детерминированный TAR (без сжатия)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, data in entries.items():
            info = _tarinfo(name, len(data))
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _targz_bytes(entries: dict[str, bytes]) -> bytes:
    """Детерминированный TAR.GZ: TAR + gzip с фиксированным mtime."""
    raw_tar = _tar_bytes(entries)
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=FIXED_MTIME) as gz:
        gz.write(raw_tar)
    return gz_buf.getvalue()


# ── Шаг 1: базовые фикстуры ───────────────────────────────────
write("clean_v4.pkl", pickle.dumps({"weights": [1.0, 2.0]}, protocol=4))
write("os_system_v4.pkl", pickle.dumps(_evil_reduce(), protocol=4))

write("obfuscated_memo_v4.pkl", (
    b"\x80\x04"            # PROTO 4
    b"\x8c\x02os"          # SHORT_BINUNICODE 'os'
    b"\x94"                # MEMOIZE
    b"\x30"                # POP
    b"\x8c\x06system"      # SHORT_BINUNICODE 'system'
    b"\x94"                # MEMOIZE
    b"\x30"                # POP
    b"\x68\x00"            # BINGET 0
    b"\x68\x01"            # BINGET 1
    b"\x93"                # STACK_GLOBAL -> os.system
    b"\x30"                # POP
    b"."
))

write(
    "multi_stream.pkl",
    pickle.dumps({"ok": 1}, protocol=4) + pickle.dumps(_evil_reduce(), protocol=4),
)

write("os_system_v0.pkl", b"cos\nsystem\n(S'echo pwned'\ntR.")

write("evil_model.pt", _zip_bytes({
    "data.pkl": pickle.dumps(_evil_reduce(), protocol=4),
    "archive/data/0": b"\x00" * 1024,
}))

# ── Шаг 2: контейнеры ─────────────────────────────────────────
write("evil_model.tar", _tar_bytes({
    "data.pkl": pickle.dumps(_evil_reduce(), protocol=4),
    "archive/data/0": b"\x00" * 1024,
}))

write("evil_model.tar.gz", _targz_bytes({
    "data.pkl": pickle.dumps(_evil_reduce(), protocol=4),
}))

inner_zip = _zip_bytes({
    "data.pkl": pickle.dumps(_evil_reduce(), protocol=4),
})
write("nested_evil.zip", _zip_bytes({
    "inner.zip": inner_zip,
    "weights.bin": b"\x00" * 512,
}))

write("hidden_pickle.zip", _zip_bytes({
    "archive/data/0": pickle.dumps(_evil_reduce(), protocol=4),
    "readme.txt": b"legit",
}))

# ZIP-bomb: 300 MB нулей сжимаются в ~300 KB при DEFLATED,
# но мы используем ZIP_STORED для детерминизма — тогда файл будет 300 MB.
# Компромисс: DEFLATED + фиксированный timestamp даёт детерминизм.
def _zip_bomb_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("clean.pkl", date_time=FIXED_ZIP_DATE)
        info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info, pickle.dumps({"ok": 1}, protocol=4))
        info2 = zipfile.ZipInfo("bomb.bin", date_time=FIXED_ZIP_DATE)
        info2.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info2, b"\x00" * (300 * 1024 * 1024))
    return buf.getvalue()

write("zip_bomb.pt", _zip_bomb_bytes())

# NPY (опционально, если numpy есть)
try:
    import numpy as np
    arr = np.array([pickle.dumps(_evil_reduce(), protocol=4)], dtype=object)
    npy_buf = io.BytesIO()
    np.save(npy_buf, arr, allow_pickle=True)
    write("evil_object.npy", npy_buf.getvalue())
except ImportError:
    print("numpy not installed — skipping evil_object.npy fixture")

# ── Шаг 3.1: контекстные правила ──────────────────────────────
# 13. REDUCE-цепочка: STACK_GLOBAL + REDUCE (классический RCE-паттерн)
write("stack_global_reduce.pkl", (
    b"\x80\x04"                          # PROTO 4
    b"\x8c\x05posix"                     # SHORT_BINUNICODE 'posix' (5)
    b"\x8c\x06system"                    # SHORT_BINUNICODE 'system' (6)
    b"\x93"                              # STACK_GLOBAL -> posix.system
    b"\x8c\x0becho pwned\x00"            # SHORT_BINUNICODE 'echo pwned\x00' (11)
    b"\x85"                              # TUPLE1
    b"R"                                 # REDUCE
    b"."
))

# 14. >2 REDUCE в потоке (many_reduces → major)
write("many_reduces.pkl", (
    b"\x80\x04"
    b"\x8c\x08builtins" b"\x8c\x04eval" b"\x93"   # builtins.eval (hard_block)
    b"\x8c\x011" b"\x85" b"R"                     # REDUCE #1
    b"\x8c\x08builtins" b"\x8c\x04eval" b"\x93"
    b"\x8c\x012" b"\x85" b"R"                     # REDUCE #2
    b"\x8c\x08builtins" b"\x8c\x04eval" b"\x93"
    b"\x8c\x013" b"\x85" b"R"                     # REDUCE #3
    b"."
))

# 15. dynamic_global: STACK_GLOBAL с не-строками на стеке
# Только dynamic_global, без hard_block: сначала кладём результат REDUCE,
# затем пытаемся STACK_GLOBAL с ним.
write("dynamic_global.pkl", (
    b"\x80\x04"
    b"\x8c\x05tuple" b"\x8c\x05tuple" b"\x93"     # tuple.tuple (не в hard, soft_major)
    b"\x8c\x011" b"\x85" b"R"                     # REDUCE → _OBJ на стеке
    b"\x8c\x03foo"                                # SHORT_BINUNICODE 'foo'
    b"\x93"                                       # STACK_GLOBAL: attr='foo', module=_OBJ → dynamic_global
    b"."
))

# 16. Легитимный импорт (soft_major, не critical) — numpy, один поток
write("legit_import.pkl", (
    b"\x80\x04"
    b"\x8c\x05numpy" b"\x8c\x05array" b"\x93"     # numpy.array (soft_major)
    b"\x8c\x011" b"\x85" b"R"
    b"."
))

# 17. importlib.import_module (hard_block, точный)
write("importlib_hard.pkl", (
    b"\x80\x04"
    b"\x8c\x09importlib" b"\x8c\x0dimport_module" b"\x93"  # importlib.import_module
    b"\x8c\x02os" b"\x85" b"R"
    b"."
))


print(f"written to {OUT}")