"""Run slow operations off the GUI thread.

Tk is not thread-safe: results travel back to the main thread through a queue
that the main loop drains with ``after()``. Callbacks therefore always run where
they are allowed to touch widgets.
"""

from __future__ import annotations

import queue
import threading
import traceback
from typing import Callable, Optional


class TaskRunner:
    """A background work queue with progress reporting and Tk-safe callbacks."""

    def __init__(self, root, interval_ms: int = 40) -> None:
        self._root = root
        self._queue: "queue.Queue" = queue.Queue()
        self._interval = interval_ms
        self._running = 0
        self._stopped = False
        self._after_id = self._root.after(interval_ms, self._poll)

    @property
    def busy(self) -> bool:
        return self._running > 0

    def stop(self) -> None:
        """Stop polling; call this before destroying the window."""
        self._stopped = True
        if self._after_id is not None:
            try:
                self._root.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def submit(
        self,
        fn: Callable,
        on_success: Optional[Callable] = None,
        on_error: Optional[Callable] = None,
        on_progress: Optional[Callable] = None,
        name: str = "crsys-task",
    ) -> None:
        """Run ``fn(report)`` in a thread; ``report(done, total)`` is optional."""
        self._running += 1
        last = [-1.0]

        def report(done: int, total: int) -> None:
            # Thin out the updates: on large files these would arrive thousands
            # of times per second and the window would spend its time redrawing.
            fraction = (done / total) if total else 1.0
            if fraction - last[0] < 0.005 and fraction < 1.0:
                return
            last[0] = fraction
            self._queue.put(("progress", on_progress, fraction))

        def target() -> None:
            try:
                result = fn(report)
            except BaseException as exc:  # unexpected errors must surface too
                self._queue.put(("error", on_error, (exc, traceback.format_exc())))
            else:
                self._queue.put(("success", on_success, result))

        threading.Thread(target=target, daemon=True, name=name).start()

    def _poll(self) -> None:
        if self._stopped:
            return
        try:
            while True:
                try:
                    kind, callback, payload = self._queue.get_nowait()
                except queue.Empty:
                    break

                if kind == "progress":
                    self._safe(callback, payload)
                    continue

                self._running -= 1
                if kind == "success":
                    self._safe(callback, payload)
                else:
                    exc, tb = payload
                    self._safe(callback, exc, tb)
        finally:
            # Rescheduling lives in the finally on purpose: if it were skipped
            # even once, the application would stay "busy" forever and no later
            # operation could ever start.
            if not self._stopped:
                self._after_id = self._root.after(self._interval, self._poll)

    @staticmethod
    def _safe(callback: Optional[Callable], *args) -> None:
        """A faulty callback should make noise, not stall the queue."""
        if callback is None:
            return
        try:
            callback(*args)
        except Exception:
            traceback.print_exc()
