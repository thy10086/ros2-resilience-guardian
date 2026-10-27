"""Fixed agent entry point for the shared stdlib-only HTTP worker.

Trusted repository paths select the worker; credentials arrive through stdin.
"""
from pathlib import Path
import runpy

if __name__ == "__main__":
    # Avoid importing guardian_core.__init__: the transport remains stdlib-only
    # and must not pay for the complete control package at each HTTP request.
    runpy.run_path(str(Path(__file__).resolve().parents[2] /
        "ros2_ws/src/guardian_core/guardian_core/http_transport.py"), run_name="__main__")
