"""ASCII-прогресс для хеширования файлов."""
import sys
import time

from auditllm.utils import format_size


class ProgressReporter:
    def __init__(self, enabled: bool = True, use_tty: bool | None = None):
        """
        Args:
            enabled: если False — все методы no-op.
            use_tty: если None — автоопределение через sys.stdout.isatty().
        """
        self._files: list[tuple[str, int]] = []  # [(name, size), ...]
        self._current_index: int = -1
        self._current_bytes: int = 0
        self._current_size: int = 0
        self._start_time: float = 0.0
        self._file_start_time: float = 0.0

        self.enabled = enabled
        if use_tty is None:
            use_tty = sys.stdout.isatty()
        self.use_tty = use_tty and enabled
        self._cancelled = False

        self._last_draw: float = 0.0
        self._current_check: str = ""
        self._check_start_time: float = 0.0
        self._total_bytes: int = 0
        self._done_bytes: int = 0
        self._check_printed: bool = False

    def start(self, files: list[tuple[str, int]]) -> None:
        """Начать прогресс. files = [(name, size_bytes), ...]."""
        if not self.enabled:
            return
        self._files = files
        self._start_time = time.monotonic()
        self._total_bytes = sum(size for _, size in files)
        self._done_bytes = 0
        if not self.use_tty:
            return

    def start_file(self, index: int) -> None:
        """Начать обработку файла с индексом index (0-based)."""
        if not self.enabled:
            return
        self._current_index = index
        self._current_bytes = 0
        self._current_size = self._files[index][1]
        self._file_start_time = time.monotonic()

        self._last_draw = time.monotonic()
        if self.use_tty:
            self._draw()

    def start_check(self, check_name: str) -> None:
        """Начать новый этап проверки (hash, header, pickle...)."""
        if not self.enabled:
            return
        self._current_check = check_name
        self._current_bytes = 0
        self._check_start_time = time.monotonic()
        self._last_draw = time.monotonic()
        # бар — только для читающих проверок (hash)
        if self.use_tty and check_name == "hash":
            self._draw()

    DRAW_INTERVAL = 0.1  # 100 мс

    def advance(self, n_bytes):
        if not self.enabled:
            return
        self._current_bytes += n_bytes
        self._done_bytes += n_bytes
        if self.use_tty:
            now = time.monotonic()
            if now - self._last_draw >= self.DRAW_INTERVAL:
                self._draw()
                self._last_draw = now

    def finish_file(self) -> None:
        """Завершить текущий файл."""
        if not self.enabled:
            return
        if self._current_bytes == 0 and self._current_size > 0:
            self._done_bytes += self._current_size
        if self.use_tty:
            if not self._check_printed:
                self._draw()
                print()
            print()  # разделитель между файлами
        else:
            print(self._render_line())

    def finish(self) -> None:
        """Завершить прогресс, стереть строку."""
        if not self.enabled:
            return
        if self.use_tty:
            print('\r\033[K', end='')

    def finish_check(self, status: str = "pass") -> None:
        """Завершить текущую проверку."""
        if not self.enabled:
            return

        check_elapsed = (
            time.monotonic() - self._check_start_time
            if self._check_start_time else 0
        )
        if self._current_check:
            if check_elapsed < 1.0:
                dur_str = f"{int(check_elapsed * 1000)} ms"
            else:
                dur_str = f"{check_elapsed:.1f}s"

            marker = {
                "pass": "✓",
                "warn": "?",
                "fail": "✗",
                "skip": "-",
            }.get(status, "?")

            self._current_bytes = self._current_size
            # бар — только для hash
            if self.use_tty and self._current_check == "hash":
                self._draw()
                print()
            print(f"  [{marker}] {self._current_check:<10} {status:<6} {dur_str:>8}")
            self._check_printed = True
            self._last_draw = time.monotonic()
        else:
            self._current_bytes = self._current_size
            self._last_draw = time.monotonic()
            if self.use_tty:
                self._draw()

    def cancel(self) -> None:
        """Пометить как отменённый."""
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    def _render_line(self) -> str:
        """Собирает строку прогресса."""
        name = self._files[self._current_index][0]
        name_short = (name[:27] + "...") if len(name) > 30 else name
        name_padded = name_short.ljust(30)

        percent = self._current_bytes / self._current_size if self._current_size else 0
        filled = int(percent * 40)
        bar = "#" * filled + "." * (40 - filled)
        pct = f"{int(percent * 100):>3}%"

        check_elapsed = (
            time.monotonic() - self._check_start_time
            if self._check_start_time else 0
        )
        speed_bps = self._current_bytes / check_elapsed if check_elapsed > 0 else 0
        speed_str = self._format_speed(speed_bps)

        file_elapsed = time.monotonic() - self._file_start_time
        elapsed_str = self._format_eta(file_elapsed)
        if percent > 0 and file_elapsed > 0:
            eta = file_elapsed * (1 - percent) / percent
            eta_str = self._format_eta(eta)
        else:
            eta_str = "--:--"

        total_pct = (
            f"{self._done_bytes / self._total_bytes * 100:.0f}%"
            if self._total_bytes else "?"
        )
        # две колонки фиксированной ширины
        file_part = f"[{self._current_index + 1}/{len(self._files)}]".ljust(8)
        bytes_part = (
            f"[{format_size(self._done_bytes)}/{format_size(self._total_bytes)}, {total_pct}]"
        ).ljust(26)

        prefix = f"  {file_part} {bytes_part} "
        check_part = f" | {self._current_check:<6}" if self._current_check else " | " + " " * 6
        return (
            f"{prefix}{name_padded} [{bar}] {pct}{check_part} | "
            f"{speed_str} | {elapsed_str} / ETA {eta_str}"
        )

    def _draw(self):
        line = self._render_line()
        print('\r\033[K' + line, end='', flush=True)

    @staticmethod
    def _format_speed(bps: float) -> str:
        if bps < 1024:
            return f"{bps:.0f} B/s"
        if bps < 1024 ** 2:
            return f"{bps / 1024:.1f} KB/s"
        if bps < 1024 ** 3:
            return f"{bps / 1024 ** 2:.1f} MB/s"
        return f"{bps / 1024 ** 3:.1f} GB/s"

    @staticmethod
    def _format_eta(sec: float) -> str:
        if sec < 0 or sec > 99999:
            return "--:--"
        m, s = divmod(int(sec), 60)
        h, m = divmod(m, 60)
        if h > 0:
            return f"{h}:{m:02d}:{s:02d}"
        return f"{m:02d}:{s:02d}"


if __name__ == "__main__":
    import time

    files = [("llama-3-8b.Q4_K_M.gguf", 4_700_000_000), ("mistral-7b.Q5_K_S.gguf", 5_100_000_000)]

    progress = ProgressReporter(enabled=True, use_tty=True)
    progress.start(files)

    for i, (name, size) in enumerate(files):
        progress.start_file(i)
        chunk = size // 20
        for _ in range(20):
            time.sleep(0.05)
            progress.advance(chunk)
        progress.finish_file()

    progress.finish()
    print("Готово!")




