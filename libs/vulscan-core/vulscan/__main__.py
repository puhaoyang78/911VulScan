# Modified 2026-10-23 for the VulScan-only product namespace.
"""Allow running `python -m vulscan`."""
from vulscan.cli import main
import sys

sys.exit(main())
