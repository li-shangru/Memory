"""Exercise the native main-file identity contract in a disposable directory."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path

from sqlcipher3 import dbapi2 as sqlcipher


def identity(path: Path) -> tuple[int, int]:
    metadata = path.stat()
    return metadata.st_dev, metadata.st_ino


def expect_error(operation: Callable[[], object], exception: type[Exception]) -> None:
    try:
        operation()
    except exception:
        return
    raise AssertionError(f"expected {exception.__name__}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="memory-native-identity-") as temporary:
        root = Path(temporary)
        path = root / "synthetic.sqlite3"
        path.touch()
        expected = identity(path)
        connection = sqlcipher.connect(path)
        # This is deliberately the first call after connect, before any key/SQL.
        assert connection.file_identity() == expected
        assert all(type(value) is int for value in connection.file_identity())
        expect_error(lambda: connection.file_identity("main"), TypeError)
        errors: list[type[BaseException]] = []

        def other_thread() -> None:
            try:
                connection.file_identity()
            except BaseException as error:
                errors.append(type(error))

        worker = threading.Thread(target=other_thread)
        worker.start()
        worker.join()
        assert errors == [sqlcipher.ProgrammingError]
        connection.close()
        expect_error(connection.file_identity, sqlcipher.ProgrammingError)

        for suffix in ("?mode=ro", "?mode=ro&immutable=1"):
            readonly = sqlcipher.connect(path.as_uri() + suffix, uri=True)
            assert readonly.file_identity() == expected
            readonly.close()

        # Open a copied replacement, then restore the original pathname before
        # asking for identity. Path stat/HAS_MOVED cannot attest the opened file.
        original = root / "original.sqlite3"
        opened_replacement = root / "replacement.sqlite3"
        path.rename(original)
        shutil.copyfile(original, path)
        replacement_identity = identity(path)
        assert replacement_identity != expected
        replaced_connection = sqlcipher.connect(path)
        path.rename(opened_replacement)
        original.rename(path)
        assert identity(path) == expected
        assert replaced_connection.file_identity() == replacement_identity
        assert replaced_connection.file_identity() != identity(path)
        replaced_connection.close()
        assert path.read_bytes() == b""
        assert opened_replacement.read_bytes() == b""

        # A concurrent SQLite callback may wait for Python/GIL progress. The
        # identity probe must refuse a busy db mutex instead of blocking it.
        shared = sqlcipher.connect(path, check_same_thread=False)
        entered = threading.Event()
        release = threading.Event()
        callback_errors: list[BaseException] = []

        def callback() -> int:
            entered.set()
            assert release.wait(10)
            return 1

        def query() -> None:
            try:
                shared.execute("SELECT synthetic_hold()").fetchone()
            except BaseException as error:
                callback_errors.append(error)

        shared.create_function("synthetic_hold", 0, callback)
        query_worker = threading.Thread(target=query)
        query_worker.start()
        assert entered.wait(10)
        try:
            expect_error(shared.file_identity, sqlcipher.OperationalError)
        finally:
            release.set()
            query_worker.join(10)
        assert not query_worker.is_alive()
        assert not callback_errors
        assert shared.file_identity() == expected
        shared.close()

        for database in (":memory:", ""):
            anonymous = sqlcipher.connect(database)
            expect_error(anonymous.file_identity, sqlcipher.OperationalError)
            anonymous.close()

        # fstat does not open/close another handle or release process-wide POSIX
        # locks held by a live SQLite transaction.
        reader = sqlcipher.connect(path)
        reader.execute("CREATE TABLE synthetic(value TEXT)")
        reader.execute("INSERT INTO synthetic VALUES ('synthetic-lock-proof')")
        reader.commit()
        reader.execute("BEGIN")
        assert reader.execute("SELECT value FROM synthetic").fetchone()
        child = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        pass
    else:
        raise AssertionError('SQLite reader lock was released')
finally:
    os.close(fd)
"""
        subprocess.run([sys.executable, "-I", "-c", child, str(path)], check=True)
        for _ in range(3):
            assert reader.file_identity() == expected
        subprocess.run([sys.executable, "-I", "-c", child, str(path)], check=True)
        assert reader.in_transaction
        reader.rollback()
        reader.close()
    print(
        "native file identity: pre-key, restored-path, readonly, immutable, "
        "closed, memory, thread, busy-mutex and lock checks passed"
    )


if __name__ == "__main__":
    main()
