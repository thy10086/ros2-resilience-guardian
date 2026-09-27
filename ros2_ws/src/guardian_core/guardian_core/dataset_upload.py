"""Bounded, read-only staging for user-uploaded dataset audit batches."""

from __future__ import annotations

import re
import shutil
import stat
import tempfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from email.message import Message
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterator


MAX_UPLOAD_BYTES = 512 * 1024 * 1024
MAX_UPLOAD_REQUEST_BYTES = MAX_UPLOAD_BYTES + 8 * 1024 * 1024
MAX_UPLOAD_FILES = 10_000
MAX_UPLOAD_FILE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_HEADER_LINE_BYTES = 64 * 1024
STREAM_CHUNK_BYTES = 64 * 1024


class DatasetUploadError(ValueError):
    """Raised when an upload cannot be safely staged."""

    def __init__(self, message: str, *, code: str = "invalid_upload", status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class UploadBatch:
    root: Path
    label: str
    files_total: int
    bytes_total: int


class _LimitedReader:
    def __init__(self, stream: BinaryIO, limit: int) -> None:
        self._stream = stream
        self.remaining = limit

    def read(self, size: int = -1) -> bytes:
        if self.remaining <= 0:
            return b""
        if size < 0:
            size = self.remaining
        size = min(size, self.remaining)
        payload = self._stream.read(size)
        self.remaining -= len(payload)
        return payload

    def read1(self, size: int = -1) -> bytes:
        return self.read(size)

    def readline(self, size: int = -1) -> bytes:
        if self.remaining <= 0:
            return b""
        if size < 0:
            size = self.remaining
        size = min(size, self.remaining)
        payload = self._stream.readline(size)
        self.remaining -= len(payload)
        return payload


class _BufferedReader:
    def __init__(self, stream: _LimitedReader) -> None:
        self._stream = stream
        self._buffer = bytearray()

    def read1(self, size: int = -1) -> bytes:
        if size < 0:
            size = max(len(self._buffer), STREAM_CHUNK_BYTES)
        if self._buffer:
            payload = bytes(self._buffer[:size])
            del self._buffer[:size]
            return payload
        return self._stream.read1(size)

    def read(self, size: int = -1) -> bytes:
        return self.read1(size)

    def readline(self, size: int = -1) -> bytes:
        output = bytearray()
        while size < 0 or len(output) < size:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                take = newline + 1
                if size >= 0:
                    take = min(take, size - len(output))
                output.extend(self._buffer[:take])
                del self._buffer[:take]
                break
            if self._buffer:
                take = len(self._buffer)
                if size >= 0:
                    take = min(take, size - len(output))
                output.extend(self._buffer[:take])
                del self._buffer[:take]
                if size >= 0 and len(output) >= size:
                    break
            chunk = self._stream.read1(STREAM_CHUNK_BYTES)
            if not chunk:
                break
            self._buffer.extend(chunk)
        return bytes(output)

    def unread(self, payload: bytes) -> None:
        if payload:
            self._buffer[:0] = payload


def _content_type_parameters(content_type: str | None) -> tuple[str, str | None]:
    if not content_type:
        raise DatasetUploadError("上传请求缺少 Content-Type", code="invalid_content_type")
    message = Message()
    message["Content-Type"] = content_type
    media_type = message.get_content_type().lower()
    boundary = message.get_param("boundary", header="Content-Type")
    if media_type != "multipart/form-data" or not boundary:
        raise DatasetUploadError("必须使用 multipart/form-data 上传文件", code="invalid_content_type")
    return media_type, boundary


def _header_parameters(value: str, header: str) -> Message:
    message = Message()
    message[header] = value
    return message


def _filename(value: str | None) -> str | None:
    if not value:
        return None
    message = _header_parameters(value, "Content-Disposition")
    filename = message.get_filename()
    return filename.strip() if isinstance(filename, str) else None


def _safe_relative_name(filename: str | None) -> str:
    if not filename:
        raise DatasetUploadError("上传文件缺少文件名", code="invalid_filename")
    if "\x00" in filename or "\\" in filename:
        raise DatasetUploadError("文件名包含不允许的路径字符", code="unsafe_filename")
    if filename.startswith("/") or re.match(r"^[A-Za-z]:", filename):
        raise DatasetUploadError("不允许上传绝对路径文件名", code="unsafe_filename")
    parts = filename.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise DatasetUploadError("文件名不能包含空路径、. 或 ..", code="unsafe_filename")
    relative = PurePosixPath(*parts).as_posix()
    if relative in {"", "."}:
        raise DatasetUploadError("上传文件名为空", code="invalid_filename")
    return relative


def _write_limited(target: BinaryIO | None, payload: bytes, state: dict[str, int], *, limit: int) -> None:
    if not payload:
        return
    state["bytes"] += len(payload)
    if state["bytes"] > MAX_UPLOAD_BYTES:
        raise DatasetUploadError("本批上传总大小不能超过 512 MiB", code="upload_too_large", status=413)
    if state["file_bytes"] + len(payload) > limit:
        raise DatasetUploadError("单个上传文件不能超过 256 MiB", code="file_too_large", status=413)
    state["file_bytes"] += len(payload)
    if target is not None:
        target.write(payload)


def _read_chunk(stream: BinaryIO, size: int) -> bytes:
    """Read currently available socket data without waiting for the full size."""

    read1 = getattr(stream, "read1", None)
    return read1(size) if callable(read1) else stream.read(size)


def _consume_part(stream: BinaryIO, boundary: bytes, target: BinaryIO | None, state: dict[str, int]) -> bool:
    """Copy one multipart part and return whether its boundary is final."""

    marker = b"\r\n--" + boundary
    buffer = bytearray()
    search_start = 0
    while True:
        chunk = _read_chunk(stream, STREAM_CHUNK_BYTES)
        if not chunk:
            raise DatasetUploadError("multipart 上传内容不完整", code="incomplete_upload")
        buffer.extend(chunk)
        while True:
            position = buffer.find(marker, search_start)
            if position < 0:
                keep = len(marker) + 2
                safe_length = len(buffer) - keep
                if safe_length > 0:
                    _write_limited(target, bytes(buffer[:safe_length]), state, limit=MAX_UPLOAD_FILE_BYTES)
                    del buffer[:safe_length]
                search_start = 0
                break
            suffix_start = position + len(marker)
            if len(buffer) < suffix_start + 2:
                search_start = position
                break
            suffix = bytes(buffer[suffix_start:suffix_start + 2])
            if suffix not in {b"\r\n", b"--"}:
                search_start = position + 1
                continue
            _write_limited(target, bytes(buffer[:position]), state, limit=MAX_UPLOAD_FILE_BYTES)
            del buffer[:suffix_start + 2]
            stream.unread(bytes(buffer))
            buffer.clear()
            state["file_bytes"] = 0
            return suffix == b"--"


def _read_header_line(stream: BinaryIO) -> bytes:
    line = stream.readline(MAX_HEADER_LINE_BYTES + 1)
    if not line or len(line) > MAX_HEADER_LINE_BYTES:
        raise DatasetUploadError("multipart 请求头过长或不完整", code="invalid_multipart")
    return line


def _parse_multipart(stream: _BufferedReader, content_type: str, root: Path) -> tuple[list[tuple[str, Path]], int]:
    _, boundary_text = _content_type_parameters(content_type)
    assert boundary_text is not None
    boundary = boundary_text.encode("utf-8")
    if len(boundary) > 200 or b"\r" in boundary or b"\n" in boundary:
        raise DatasetUploadError("multipart boundary 无效", code="invalid_multipart")

    first = _read_header_line(stream)
    opening = b"--" + boundary
    first_line = first.rstrip(b"\r\n")
    if first_line not in {opening, opening + b"--"}:
        raise DatasetUploadError("multipart 上传边界无效", code="invalid_multipart")

    incoming = root / "incoming"
    incoming.mkdir()
    records: list[tuple[str, Path]] = []
    total_bytes = 0
    seen_names: set[str] = set()
    final = first_line == opening + b"--"

    while not final:
        headers: dict[str, str] = {}
        while True:
            line = _read_header_line(stream)
            if line in {b"\r\n", b"\n"}:
                break
            try:
                name, value = line.decode("utf-8", "strict").split(":", 1)
            except (UnicodeDecodeError, ValueError):
                raise DatasetUploadError("multipart 文件头无效", code="invalid_multipart") from None
            headers[name.strip().lower()] = value.strip()

        filename = _filename(headers.get("content-disposition"))
        relative = _safe_relative_name(filename) if filename is not None else None
        target = None
        record = None
        if relative is not None:
            if relative in seen_names:
                raise DatasetUploadError(f"上传批次包含重复文件：{relative}", code="duplicate_filename")
            if len(records) >= MAX_UPLOAD_FILES:
                raise DatasetUploadError("单批文件数不能超过 10000 个", code="too_many_files", status=413)
            target_path = incoming / Path(*PurePosixPath(relative).parts)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target = target_path.open("wb")
            record = (relative, target_path)
            seen_names.add(relative)

        state = {"bytes": total_bytes, "file_bytes": 0}
        try:
            final = _consume_part(stream, boundary, target, state)
        finally:
            if target is not None:
                target.close()
        total_bytes = state["bytes"]
        if record is not None:
            records.append(record)

    if final:
        trailer = stream.read(2)
        if trailer not in {b"", b"\r\n"}:
            raise DatasetUploadError("multipart 上传结束标记无效", code="invalid_multipart")
    return records, total_bytes


def _validate_archive_member(name: str) -> str:
    return _safe_relative_name(name.replace("\\", "/"))


def _extract_zip(archive: Path, destination: Path) -> tuple[int, int]:
    files_total = 0
    bytes_total = 0
    seen_names: set[str] = set()
    try:
        bundle = zipfile.ZipFile(archive)
    except (OSError, zipfile.BadZipFile) as error:
        raise DatasetUploadError(f"ZIP 文件无法读取：{type(error).__name__}", code="invalid_zip") from error
    with bundle:
        for info in bundle.infolist():
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                raise DatasetUploadError("不接受加密 ZIP 文件", code="encrypted_archive")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise DatasetUploadError("ZIP 不允许包含符号链接", code="unsafe_archive")
            relative = _validate_archive_member(info.filename)
            if relative in seen_names:
                raise DatasetUploadError(f"ZIP 包含重复文件：{relative}", code="duplicate_filename")
            seen_names.add(relative)
            files_total += 1
            if files_total > MAX_UPLOAD_FILES:
                raise DatasetUploadError("单批文件数不能超过 10000 个", code="too_many_files", status=413)
            target = destination / Path(*PurePosixPath(relative).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            try:
                with bundle.open(info, "r") as source, target.open("wb") as output:
                    while True:
                        block = source.read(STREAM_CHUNK_BYTES)
                        if not block:
                            break
                        written += len(block)
                        bytes_total += len(block)
                        if written > MAX_UPLOAD_FILE_BYTES or bytes_total > MAX_ARCHIVE_BYTES:
                            raise DatasetUploadError("ZIP 展开后的数据超过安全上限", code="archive_too_large", status=413)
                        output.write(block)
            except DatasetUploadError:
                raise
            except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                raise DatasetUploadError(f"ZIP 文件展开失败：{type(error).__name__}", code="invalid_zip") from error
    return files_total, bytes_total


@contextmanager
def stage_multipart_upload(stream: BinaryIO, content_type: str, content_length: int) -> Iterator[UploadBatch]:
    """Stage one upload batch on disk and remove it after the caller finishes."""

    if content_length < 0:
        raise DatasetUploadError("上传请求长度无效", code="invalid_content_length")
    if content_length > MAX_UPLOAD_REQUEST_BYTES:
        raise DatasetUploadError("本批上传请求不能超过 520 MiB", code="upload_too_large", status=413)

    temporary_root = Path(tempfile.mkdtemp(prefix="guardian-dataset-"))
    try:
        limited_stream = _LimitedReader(stream, content_length)
        records, total_bytes = _parse_multipart(_BufferedReader(limited_stream), content_type, temporary_root)
        if not records:
            raise DatasetUploadError("请选择至少一个文件或文件夹", code="empty_upload")
        label = "上传批次"
        if len(records) == 1 and records[0][0].lower().endswith(".zip"):
            dataset_root = temporary_root / "dataset"
            dataset_root.mkdir()
            label = Path(records[0][0]).stem or "ZIP 上传批次"
            files_total, bytes_total = _extract_zip(records[0][1], dataset_root)
            if files_total == 0:
                raise DatasetUploadError("ZIP 文件中没有可审计文件", code="empty_archive")
        else:
            source_root = temporary_root / "incoming"
            dataset_root = source_root
            files_total = len(records)
            bytes_total = total_bytes
            first_parts = PurePosixPath(records[0][0]).parts
            if len(first_parts) > 1:
                common_top = first_parts[0]
                if all(PurePosixPath(relative).parts[0] == common_top for relative, _ in records):
                    label = common_top
        yield UploadBatch(dataset_root, label, files_total, bytes_total)
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)


__all__ = [
    "DatasetUploadError",
    "MAX_UPLOAD_BYTES",
    "MAX_UPLOAD_FILES",
    "MAX_UPLOAD_FILE_BYTES",
    "MAX_UPLOAD_REQUEST_BYTES",
    "UploadBatch",
    "stage_multipart_upload",
]
