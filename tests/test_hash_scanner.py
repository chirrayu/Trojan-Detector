"""Tests for the hash scanner module."""

import tempfile
from pathlib import Path

import pytest

from trojandetector.scanner.hash_scanner import hash_file


class TestHashFile:
    """hash_file() tests."""

    def test_hash_known_content(self, tmp_path: Path) -> None:
        """SHA-256 of known content must match the expected digest."""
        test_file = tmp_path / "hello.txt"
        test_file.write_text("hello world")

        result = hash_file(test_file)

        # sha256("hello world") is well-known
        assert result.sha256 == (
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        )
        assert result.file_size == 11
        assert result.md5
        assert result.sha1

    def test_hash_empty_file(self, tmp_path: Path) -> None:
        """Hashing an empty file should succeed."""
        test_file = tmp_path / "empty.bin"
        test_file.write_bytes(b"")

        result = hash_file(test_file)

        # sha256 of empty input
        assert result.sha256 == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert result.file_size == 0

    def test_hash_binary_file(self, tmp_path: Path) -> None:
        """Binary content should hash correctly."""
        test_file = tmp_path / "binary.bin"
        test_file.write_bytes(bytes(range(256)))

        result = hash_file(test_file)
        assert len(result.sha256) == 64
        assert result.file_size == 256

    def test_file_not_found(self) -> None:
        """FileNotFoundError if file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            hash_file("nonexistent_file_12345.bin")

    def test_directory_raises(self, tmp_path: Path) -> None:
        """IsADirectoryError if path is a directory."""
        with pytest.raises(IsADirectoryError):
            hash_file(tmp_path)
