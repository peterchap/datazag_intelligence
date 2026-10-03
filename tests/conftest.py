"""Suite-wide test configuration."""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import observatory  # noqa: E402

# Reports read the corpus size from the live Observatory through a process cache.
# Seed it as unavailable so no test reaches R2; tests that need figures inject
# tests.estate_helpers.fixture_observatory() explicitly.
observatory._CACHE = observatory.Observatory.unavailable()
