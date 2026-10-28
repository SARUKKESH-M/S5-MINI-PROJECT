"""
CodeSentinel — Step 6T-4: Analysis Caching & Reuse Engine

Provides deterministic, secret-safe local caching for AST and security analysis.
Invalidates stale entries upon file modification and handles corrupted cache entries safely.
"""

from collections import OrderedDict
import copy
import hashlib
import json
import os
from pathlib import Path
import threading
from typing import Any, Dict, Optional
import uuid

try:
    from backend.app.core.security import sanitize_sensitive_text
except ImportError:
    def sanitize_sensitive_text(val: str) -> str:
        return val


DEFAULT_MAX_CACHE_ENTRIES = 500


class AnalysisCache:
    """Deterministic, thread-safe bounded local cache for security analysis results."""

    def __init__(self, cache_dir: Optional[str] = None, max_entries: int = DEFAULT_MAX_CACHE_ENTRIES):
        if not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError(f"max_entries must be an integer >= 1, got {max_entries}")

        self._lock = threading.Lock()
        self._max_entries = max_entries
        self._memory_cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._path_versions: Dict[str, int] = {}
        self._stats = {"hits": 0, "misses": 0}

        if cache_dir:
            self._cache_dir = Path(cache_dir).resolve()
        else:
            self._cache_dir = Path(__file__).parent.parent.parent / "data" / "cache"

        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def compute_file_hash(self, content: str) -> str:
        """Computes deterministic SHA-256 hash of file content string."""
        if not isinstance(content, str):
            content = str(content)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def generate_cache_key(self, file_path: str, file_hash: str, policy_name: str = "default") -> str:
        """Generates a deterministic SHA-256 cache key string."""
        raw_key = f"{file_path}:{file_hash}:{policy_name}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def get(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a cached analysis result by key.
        Returns None on cache miss or corrupted entry.
        Returns a defensive deepcopy to guarantee caller mutation isolation.
        """
        if not cache_key or not isinstance(cache_key, str):
            return None

        with self._lock:
            # 1. In-memory cache hit: promote to most recently used and return defensive copy
            if cache_key in self._memory_cache:
                self._memory_cache.move_to_end(cache_key, last=True)
                self._stats["hits"] += 1
                return copy.deepcopy(self._memory_cache[cache_key])

            # 2. Disk cache file check
            disk_file = self._cache_dir / f"{cache_key}.json"
            if not disk_file.exists():
                self._stats["misses"] += 1
                return None

            try:
                data_str = disk_file.read_text(encoding="utf-8")
                cached_obj = json.loads(data_str)
                if not isinstance(cached_obj, dict):
                    raise ValueError("Cached payload is not a valid dictionary")

                # Populate in-memory LRU cache from disk hit
                self._memory_cache[cache_key] = cached_obj
                self._memory_cache.move_to_end(cache_key, last=True)
                if len(self._memory_cache) > self._max_entries:
                    self._memory_cache.popitem(last=False)

                self._stats["hits"] += 1
                return copy.deepcopy(cached_obj)
            except Exception:
                # Corrupted disk file: safe to unlink under lock without racing concurrent replace
                try:
                    disk_file.unlink(missing_ok=True)
                except Exception:
                    pass

            self._stats["misses"] += 1
            return None

    def set(self, cache_key: str, value: Dict[str, Any]) -> None:
        """
        Stores an analysis result in cache.
        Ensures sensitive text is sanitized before caching.
        Employs path versioning to abort stale writes if invalidate() occurred mid-serialization.
        """
        if not cache_key or not isinstance(value, dict):
            return

        file_path = str(value.get("file_path", ""))

        # Capture start version under lock to detect in-flight invalidations
        with self._lock:
            start_version = self._path_versions.get(file_path, 0)

        # Sanitize text fields and serialize to JSON outside lock to avoid blocking
        sanitized_val = json.loads(sanitize_sensitive_text(json.dumps(value)))
        json_payload = json.dumps(sanitized_val, indent=2)

        # Isolated unique temporary file path for atomic write
        tmp_file = self._cache_dir / f"{cache_key}.tmp.{uuid.uuid4().hex}"
        write_succeeded = False
        try:
            tmp_file.write_text(json_payload, encoding="utf-8")
            write_succeeded = True
        except Exception:
            try:
                tmp_file.unlink(missing_ok=True)
            except Exception:
                pass

        with self._lock:
            # Check if an invalidate() for this file_path was executed while serializing
            current_version = self._path_versions.get(file_path, 0)
            if current_version != start_version:
                # Stale write detected: invalidate() occurred concurrently. Abort commit.
                if write_succeeded:
                    try:
                        tmp_file.unlink(missing_ok=True)
                    except Exception:
                        pass
                return

            # Atomically replace destination disk file
            if write_succeeded and tmp_file.exists():
                disk_file = self._cache_dir / f"{cache_key}.json"
                try:
                    os.replace(tmp_file, disk_file)
                except Exception:
                    try:
                        tmp_file.unlink(missing_ok=True)
                    except Exception:
                        pass

            # Update in-memory LRU cache
            self._memory_cache[cache_key] = sanitized_val
            self._memory_cache.move_to_end(cache_key, last=True)
            if len(self._memory_cache) > self._max_entries:
                self._memory_cache.popitem(last=False)

    def invalidate(self, file_path: str) -> None:
        """Invalidates in-memory and disk entries associated with file_path."""
        if not file_path or not isinstance(file_path, str):
            return

        norm_path = file_path.replace("\\", "/").strip("/")

        with self._lock:
            # Increment path version to invalidate any concurrent in-flight set()
            self._path_versions[file_path] = self._path_versions.get(file_path, 0) + 1
            if norm_path != file_path:
                self._path_versions[norm_path] = self._path_versions.get(norm_path, 0) + 1

            to_delete = [
                k for k, v in self._memory_cache.items()
                if v.get("file_path") == file_path or str(v.get("file_path", "")).replace("\\", "/").strip("/") == norm_path
            ]
            for k in to_delete:
                del self._memory_cache[k]
                try:
                    (self._cache_dir / f"{k}.json").unlink(missing_ok=True)
                except Exception:
                    pass

    def clear(self) -> None:
        """Clears memory and disk cache contents."""
        with self._lock:
            self._memory_cache.clear()
            self._path_versions.clear()
            self._stats = {"hits": 0, "misses": 0}
            if self._cache_dir.exists():
                for f in self._cache_dir.glob("*.json"):
                    try:
                        f.unlink(missing_ok=True)
                    except Exception:
                        pass
                for f in self._cache_dir.glob("*.tmp.*"):
                    try:
                        f.unlink(missing_ok=True)
                    except Exception:
                        pass

    def get_stats(self) -> Dict[str, int]:
        """Returns current cache hit/miss statistics."""
        with self._lock:
            return dict(self._stats)


# Global analysis cache instance singleton
analysis_cache = AnalysisCache()
