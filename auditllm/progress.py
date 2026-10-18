"""ASCII-прогресс для хеширования файлов."""
import sys
import time


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

    def start(self, files: list[tuple[str, int]]) -> None:
        """Начать прогресс. files = [(name, size_bytes), ...]."""
        if not self.enabled:
            return
        self._files = files
        self._start_time = time.monotonic()
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
        # _file_start_time НЕ сбрасываем — общее время файла
        self._last_draw = time.monotonic()
        if self.use_tty:
            self._draw()

    DRAW_INTERVAL = 0.1  # 100 мс

    def advance(self, n_bytes):
        if not self.enabled:
            return
        self._current_bytes += n_bytes
        if self.use_tty:
            now = time.monotonic()
            if now - self._last_draw >= self.DRAW_INTERVAL:
                self._draw()
                self._last_draw = now

    def finish_file(self) -> None:
        """Завершить текущий файл."""
        if not self.enabled:
            return
        if self.use_tty:
            # Нарисовать финальное состояние (100%) с итоговым временем файла
            self._draw()
            print()
        else:
            print(self._render_line())

    def finish(self) -> None:
        """Завершить прогресс, стереть строку."""
        if not self.enabled:
            return
        if self.use_tty:
            print('\r\033[K', end='')

    def finish_check(self) -> None:
        """Завершить текущую проверку (заполнить до 100%)."""
        if not self.enabled:
            return
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

        # Elapsed — общее время файла (от начала файла, не проверки)
        elapsed_sec = time.monotonic() - self._file_start_time

        # Скорость — текущей проверки (байты / время файла)
        speed_bps = self._current_bytes / elapsed_sec if elapsed_sec > 0 else 0
        speed_str = self._format_speed(speed_bps)

        elapsed_str = self._format_eta(elapsed_sec)

        prefix = f"  [{self._current_index + 1}/{len(self._files)}] "
        check_part = f" | {self._current_check}" if self._current_check else ""
        return f"{prefix}{name_padded} [{bar}] {pct}{check_part} | {speed_str} | {elapsed_str}"

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




