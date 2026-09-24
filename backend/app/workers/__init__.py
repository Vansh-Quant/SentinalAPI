"""Background workers.

Phase 1 reserves this package for the scan worker (Phase 2): it will pull
queued scans, drive the sandboxed scanner against explicitly provisioned
sandbox APIs, and persist findings. No internet-wide scanning.
"""
