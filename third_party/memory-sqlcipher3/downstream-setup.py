"""Memory's narrow downstream build of the sqlcipher3 0.6.2 wrapper."""

from __future__ import annotations

import glob
import os
import sys

from setuptools import Extension, setup


def quote_argument(argument: str) -> str:
    return f'"{argument}"'


sqlcipher_prefix = os.environ["MEMORY_SQLCIPHER_PREFIX"]
openssl_prefix = os.environ["MEMORY_OPENSSL_PREFIX"]
define_macros = [
    ("MODULE_NAME", quote_argument("sqlcipher3.dbapi2")),
    ("HAVE_STDINT_H", "1"),
    ("inline", "__inline"),
]
extra_compile_args = ["-Qunused-arguments"] if sys.platform == "darwin" else []

module = Extension(
    name="sqlcipher3._sqlite3",
    # The narrowly patched upstream wrapper. SQLCipher is the separately pinned static
    # archive, never the stale vendor/sqlite3.c shipped in the wrapper sdist.
    sources=glob.glob("src/*.c"),
    extra_objects=[
        os.path.join(sqlcipher_prefix, "lib", "libsqlite3.a"),
        os.path.join(openssl_prefix, "lib", "libcrypto.a"),
    ],
    define_macros=define_macros,
    include_dirs=["./src", os.path.join(sqlcipher_prefix, "include", "sqlcipher")],
    extra_compile_args=extra_compile_args,
    extra_link_args=["-lm"],
    language="c",
)

setup(
    name="memory-sqlcipher3",
    version="0.6.2+sqlcipher4.17.0.memory1",
    package_dir={"sqlcipher3": "sqlcipher3"},
    packages=["sqlcipher3"],
    ext_modules=[module],
)
