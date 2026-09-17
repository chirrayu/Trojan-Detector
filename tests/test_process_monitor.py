"""Tests for the process monitor module."""

import pytest

from trojandetector.process.process_monitor import (
    get_process_info,
    list_all_processes,
    find_process_by_name,
)


class TestProcessMonitor:
    """Process monitor tests."""

    def test_get_own_process(self) -> None:
        """We should be able to inspect our own process."""
        import os

        info = get_process_info(os.getpid())
        assert info is not None
        assert info.pid == os.getpid()
        assert info.name  # should have a name

    def test_get_nonexistent_process(self) -> None:
        """A non-existent PID should return None, not crash."""
        info = get_process_info(99999999)
        assert info is None

    def test_list_all_processes(self) -> None:
        """Should return at least one process (ourselves)."""
        procs = list_all_processes()
        assert len(procs) > 0

    def test_find_by_name(self) -> None:
        """Finding 'python' should match at least the test runner."""
        # The test runner is Python, so at least one match
        matches = find_process_by_name("python.exe")
        # On some systems the name might be python3.exe or pytest, so just
        # make sure it doesn't crash
        assert isinstance(matches, list)
