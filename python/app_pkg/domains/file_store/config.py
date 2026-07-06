"""file_store config — every knob is env-backed (12-factor) through the shared env_int part (so the parse + clamp
is IDENTICAL in python/go/node); the defaults are the safe local ones. The provider is selected ONCE
(FILE_STORE_PROVIDER). Read fresh on each call so a test can set the env and see it take effect."""
import os

from ...parts.env_int import env_int

# the object backend: 'store' (durable runtime seam, default + deterministic oracle) or 's3' (fail-loud stub).
FILE_STORE_PROVIDER = os.getenv("FILE_STORE_PROVIDER", "store")
FILE_STORE_S3_BUCKET = os.getenv("FILE_STORE_S3_BUCKET", "")       # NOT S3_BUCKET (that belongs to the `storage` domain)
FILE_STORE_S3_ENDPOINT = os.getenv("FILE_STORE_S3_ENDPOINT", "")


def max_bytes() -> int:
    # max DECODED object size. Hi-clamp 786000 is the honest transport ceiling: the wire cap is 1 MiB and base64
    # inflates 4/3, so max decoded = 3*floor((1048576 - ~28 envelope)/4) ~= 786411; 786432 is ALWAYS 413 and would
    # be a configured lie. A within-cap envelope carrying an over-cap DECODED body is this domain's 422.
    return env_int(os.getenv("FILE_STORE_MAX_BYTES"), 524288, 1, 786000)


def max_keys() -> int:
    # per-owner file-COUNT cap (the partition-COUNT bound). Hi-clamp 10000, NOT 100000: the index row is rewritten
    # through the write-lock-holding do() on EVERY mutation, so the worst-case row must stay bounded.
    return env_int(os.getenv("FILE_STORE_MAX_KEYS"), 1000, 1, 10000)


def max_total_bytes() -> int:
    return env_int(os.getenv("FILE_STORE_MAX_TOTAL_BYTES"), 52428800, 1, 2 ** 40)   # per-owner byte quota (50 MiB)
