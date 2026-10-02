"""Run mypy 2.3.1 Python sources without loading the blocked librt extension.

Only transient, non-incremental checks are supported. The Python writer serves
option comparisons and throwaway cache output; all binary reads fail loudly.
"""

import base64
import runpy
import struct
import sys
import tempfile
import types
from pathlib import Path


def unavailable(*_args: object, **_kwargs: object) -> None:
    raise RuntimeError("librt binary serialization was invoked in pure Python check")


class WriteBuffer:
    def __init__(self) -> None:
        self.data = bytearray()

    def getvalue(self) -> bytes:
        return bytes(self.data)


def write_bool(data: WriteBuffer, value: bool) -> None:
    data.data.append(int(value))


def write_str(data: WriteBuffer, value: str) -> None:
    raw = value.encode("utf-8")
    data.data.extend(struct.pack("<I", len(raw)))
    data.data.extend(raw)


def write_bytes(data: WriteBuffer, value: bytes) -> None:
    data.data.extend(struct.pack("<I", len(value)))
    data.data.extend(value)


def write_int(data: WriteBuffer, value: int) -> None:
    write_str(data, str(value))


def write_float(data: WriteBuffer, value: float) -> None:
    data.data.extend(struct.pack("<d", value))


def write_tag(data: WriteBuffer, value: int) -> None:
    data.data.append(value)


def cache_version() -> int:
    return 1


package = types.ModuleType("librt")
package.__path__ = []
internal = types.ModuleType("librt.internal")
base64_module = types.ModuleType("librt.base64")

for name in (
    "ReadBuffer",
    "read_bool",
    "read_str",
    "read_bytes",
    "read_float",
    "read_int",
    "read_tag",
    "extract_symbol",
):
    setattr(internal, name, unavailable)

internal.WriteBuffer = WriteBuffer
internal.write_bool = write_bool
internal.write_str = write_str
internal.write_bytes = write_bytes
internal.write_int = write_int
internal.write_float = write_float
internal.write_tag = write_tag
internal.cache_version = cache_version

base64_module.b64encode = base64.b64encode
base64_module.urlsafe_b64encode = base64.urlsafe_b64encode
sys.modules["librt"] = package
sys.modules["librt.internal"] = internal
sys.modules["librt.base64"] = base64_module

if any(
    arg.startswith(("--incremental", "--cache-dir", "--num-workers", "-j"))
    for arg in sys.argv[1:]
):
    raise SystemExit("This launcher requires its own no-incremental, isolated-cache settings")

with tempfile.TemporaryDirectory(prefix="ns067-mypy-", dir=Path.cwd()) as cache_dir:
    sys.argv = ["mypy", "--no-incremental", f"--cache-dir={cache_dir}", *sys.argv[1:]]
    runpy.run_module("mypy", run_name="__main__")
