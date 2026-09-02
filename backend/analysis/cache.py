"""
CodeSentinel — Step 6T-4: Analysis Caching & Reuse Engine

Provides deterministic, secret-safe local caching for AST and security analysis.
Invalidates stale entries upon file modification and handles corrupted cache entries safely.
"""

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from backend.app.core.security import sanitize_sensitive_text
except ImportError:
    def sanitize_sensitive_text(val: str) -> str:
        return val


class AnalysisCache:
    """Deterministic, thread-safe local cache for security analysis results."""

    def __init__(self, cache_dir: Optional[str] = None):
        self._lock = threading.Lock()
        self._memory_cache: Dict[str, Dict[str, Any]] = {}
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
        """
        if not cache_key or not isinstance(cache_key, str):
            return None

        with self._lock:
            # 1. Check in-memory cache first
            if cache_key in self._memory_cache:
                self._stats["hits"] += 1
                return self._memory_cache[cache_key]

            # 2. Check disk cache file
            disk_file = self._cache_dir / f"{cache_key}.json"
            if not disk_file.exists():
                self._stats["misses"] += 1
                return None

            try:
                data_str = disk_file.read_text(encoding="utf-8")
                cached_obj = json.loads(data_str)
                if isinstance(cached_obj, dict):
                    self._memory_cache[cache_key] = cached_obj
                    self._stats["hits"] += 1
                    return cached_obj
            except Exception:
                # Corrupted cache file: fail open (treat as cache miss) and remove file
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
        """
        if not cache_key or not isinstance(value, dict):
            return

        # Sanitize text fields in value to prevent secret storage
        sanitized_val = json.loads(sanitize_sensitive_text(json.dumps(value)))

        with self._lock:
            self._memory_cache[cache_key] = sanitized_val
            try:
                disk_file = self._cache_dir / f"{cache_key}.json"
                disk_file.write_text(json.dumps(sanitized_val, indent=2), encoding="utf-8")
            except Exception:
                pass

    def invalidate(self, file_path: str) -> None:
        """Invalidates in-memory and disk entries associated with file_path."""
        with self._lock:
            to_delete = [k for k, v in self._memory_cache.items() if v.get("file_path") == file_path]
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
            self._stats = {"hits": 0, "misses": 0}
            if self._cache_dir.exists():
                for f in self._cache_dir.glob("*.json"):
                    try:
                        f.unlink()
                    except Exception:
                        pass

    def get_stats(self) -> Dict[str, int]:
        """Returns current cache hit/miss statistics."""
        with self._lock:
            return dict(self._stats)


# Global analysis cache instance singleton
analysis_cache = AnalysisCache()
