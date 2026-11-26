"""Генератор фикстур для pickle-сканера.

Запуск: python -m tests.fixtures.gen_pickle_fixtures
Фикстуры пишутся в tests/fixtures/pickle/ и коммитятся в git.
"""
from __future__ import annotations

import io
import pickle
import zipfile
from pathlib import Path

OUT = Path(__file__).parent / "pickle"
OUT.mkdir(parents=True, exist_ok=True)


def _evil_reduce():
    class Evil:
        def __reduce__(self):
            import os
            return (os.system, ("echo pwned",))
    return Evil()


def write(name: str, data: bytes) -> None:
    (OUT / name).write_bytes(data)


# 1. Чистый протокол 4
write("clean_v4.pkl", pickle.dumps({"weights": [1.0, 2.0]}, protocol=4))

# 2. os.system через __reduce__, протокол 4
write("os_system_v4.pkl", pickle.dumps(_evil_reduce(), protocol=4))

# 3. Memo-обфускация: строки уходят в memo, извлекаются BINGET, POP чистит стек
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

# 4. Два потока подряд: чистый + вредоносный
write(
    "multi_stream.pkl",
    pickle.dumps({"ok": 1}, protocol=4) + pickle.dumps(_evil_reduce(), protocol=4),
)

# 5. Protocol 0, GLOBAL os\nsystem (без magic 0x80)
write("os_system_v0.pkl", b"cos\nsystem\n(S'echo pwned'\ntR.")

# 6. ZIP-контейнер (.pt) с вредоносным data.pkl
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as zf:
    zf.writestr("data.pkl", pickle.dumps(_evil_reduce(), protocol=4))
    zf.writestr("archive/data/0", b"\x00" * 1024)
write("evil_model.pt", buf.getvalue())

print(f"written to {OUT}")
