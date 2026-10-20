"""Простой ASCII-спиннер для индикации процесса.

Использование:
    with Spinner(prefix="Processing: ") as s:
        s.update("file1.gguf — header")
        do_work()
        s.update("file1.gguf — hash")
        do_more_work()

В non-TTY (pipe, redirect) — no-op.
"""
import sys
import threading
import time


class Spinner:
    """Спиннер для индикации процесса (как в ollama/docker).

    Фоновый поток рисует кадры, пока основной поток работает.
    """

    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    FRAMES_ASCII = ["|", "/", "-", "\\"]

    def __init__(
        self,
        enabled: bool = True,
        prefix: str = "",
        interval: float = 0.1,
        use_ascii: bool = False,
    ):
        """Создаёт спиннер.

        Args:
            enabled: если False или не TTY — no-op.
            prefix: префикс перед кадром.
            interval: интервал между кадрами (сек).
            use_ascii: использовать ASCII-кадры (для не-UTF терминалов).
        """
        self.enabled = enabled and sys.stdout.isatty()
        self.prefix = prefix
        self.interval = interval
        self.frames = self.FRAMES_ASCII if use_ascii else self.FRAMES
        self.message = ""
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._frame_idx = 0
        self._start_time = 0.0

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    def start(self) -> None:
        """Запустить спиннер."""
        if not self.enabled:
            return
        self._start_time = time.monotonic()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Остановить спиннер и очистить строку."""
        if not self.enabled:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        # Очистить строку
        sys.stdout.write("\r" + " " * 120 + "\r")
        sys.stdout.flush()

    def update(self, message: str) -> None:
        """Обновить сообщение (потокобезопасно)."""
        self.message = message

    def _run(self) -> None:
        """Фоновый цикл рисования."""
        while not self._stop_event.is_set():
            frame = self.frames[self._frame_idx % len(self.frames)]
            elapsed = time.monotonic() - self._start_time
            line = f"{self.prefix}{frame} {self.message} ({elapsed:.1f}s)"
            # \r — начало строки, обрезаем до 120 символов
            sys.stdout.write("\r" + line[:120].ljust(120))
            sys.stdout.flush()
            self._frame_idx += 1
            self._stop_event.wait(self.interval)





















