"""storage config — every knob is env-backed (12-factor); the defaults are the safe local ones."""
import os

STORAGE_PROVIDER = os.getenv("STORAGE_PROVIDER", "store")   # store (durable, default) | s3 (wire a client)
S3_BUCKET = os.getenv("S3_BUCKET", "")
S3_ENDPOINT = os.getenv("S3_ENDPOINT", "")
