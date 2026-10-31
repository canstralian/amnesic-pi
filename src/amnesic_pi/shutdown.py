"""Turn CLI termination into a bounded containment opportunity."""

from __future__ import annotations

import signal
import threading
from contextlib import contextmanager


class ShutdownRequested(KeyboardInterrupt):
    def __init__(self, signum: int):
        super().__init__(signal.Signals(signum).name)
        self.signum = signum


def _request_shutdown(signum, frame):
    raise ShutdownRequested(signum)


@contextmanager
def shutdown_signals(ignore: bool = False):
    """Restore callers' handlers; change nothing from a worker thread.

    Cleanup temporarily ignores SIGINT/SIGTERM so a second request cannot
    interrupt forwarding revocation. Kernel subprocesses have their own timeout.
    SIGKILL and power loss cannot be handled by Python.
    """
    previous = {}
    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(
                signum, signal.SIG_IGN if ignore else _request_shutdown
            )
    try:
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
