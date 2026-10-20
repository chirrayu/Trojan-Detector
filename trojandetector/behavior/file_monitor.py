"""Watch a directory for file creation, modification, and deletion events."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from typing import Callable

try:
    from watchdog.events import FileSystemEventHandler as _WatchdogHandler
except ImportError:
    class _WatchdogHandler:
        """Import-time fallback so non-monitoring commands stay usable."""
        pass


class FileEventHandler(_WatchdogHandler):
    """Watchdog handler that emits small, serializable filesystem events."""

    def __init__(self, callback: Callable[[dict], None] | None = None) -> None:
        if not hasattr(self, "dispatch"):
            raise RuntimeError("File monitoring requires the watchdog package")
        super().__init__()
        self.callback = callback

    def on_any_event(self, event) -> None:
        if event.is_directory or event.event_type not in {"created", "modified", "deleted", "moved"}:
            return
        item = {
            "event_type": event.event_type,
            "path": str(getattr(event, "dest_path", None) or event.src_path),
            "source_path": str(event.src_path),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if self.callback:
            self.callback(item)


def watch_directory(
    path: str | Path,
    callback: Callable[[dict], None] | None = None,
    recursive: bool = True,
    stop_event: Event | None = None,
) -> None:
    """Watch ``path`` until interrupted or ``stop_event`` is set."""
    try:
        from watchdog.observers import Observer
    except ImportError as exc:
        raise RuntimeError("File monitoring requires the watchdog package") from exc
    directory = Path(path).expanduser().resolve()
    if not directory.is_dir():
        raise NotADirectoryError(directory)
    handler = FileEventHandler(callback)
    observer = Observer()
    observer.schedule(handler, str(directory), recursive=recursive)
    observer.start()
    stop = stop_event or Event()
    try:
        while not stop.wait(0.25):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()


def watch_configured_directories(callback=None, stop_event: Event | None = None) -> None:
    """Convenience API for the configured home directory."""
    watch_directory(Path.home(), callback=callback, stop_event=stop_event)
