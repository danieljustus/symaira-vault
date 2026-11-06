#!/usr/bin/env python3
"""Selftest: the intake/watch contract runs both implementations in a pinned zone."""
import os
from pathlib import Path
import unittest
from unittest import mock

import intake_watch_contract as contract


class IsolationTests(unittest.TestCase):
    def test_zone_is_pinned_whatever_the_host_says(self):
        for host in ("Asia/Tokyo", "America/Los_Angeles", ""):
            with mock.patch.dict(os.environ, {"TZ": host}):
                self.assertEqual(contract.isolated(Path("/x"))["TZ"], "UTC", host)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TZ", None)
            self.assertEqual(contract.isolated(Path("/x"))["TZ"], "UTC")


if __name__ == "__main__":
    unittest.main()
