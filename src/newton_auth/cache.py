import sys
import threading
import time
from collections import OrderedDict


class BoundedLRUCache:
    ENTRY_OVERHEAD = 128

    def __init__(self, max_mb: int = 1):
        self.max_bytes = max_mb * 1024 * 1024
        self._cache = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            ttl = entry.get("client_cache_ttl_seconds")
            if ttl is not None and (ttl == 0 or time.time() - entry["_cached_at"] > ttl):
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return entry

    def set(self, key, value):
        with self._lock:
            entry = {**value, "_cached_at": time.time()}
            self._cache[key] = entry
            self._cache.move_to_end(key)
            self._evict()

    def _evict(self):
        while self._approx_size() > self.max_bytes and self._cache:
            self._cache.popitem(last=False)

    def _approx_size(self):
        return sum(sys.getsizeof(v) + self.ENTRY_OVERHEAD for v in self._cache.values())
