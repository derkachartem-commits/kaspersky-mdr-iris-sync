"""Token rotation tests: serialization, 409 recovery, persist-before-return."""

from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from mdr_iris_sync.mdr_client import MDRTokenError, MDRTokenStore


def jwt(exp_offset: int) -> str:
    """Build a dummy JWT with the given ``exp`` offset (no signature check)."""
    import base64

    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + exp_offset}).encode()
    ).decode().rstrip("=")
    return f"header.{payload}.signature"


class FakeResponse:
    def __init__(self, status: int, body: dict | None = None, text: str = "") -> None:
        self.status_code = status
        self._body = body or {}
        self.text = text or json.dumps(self._body)

    def json(self) -> dict:
        return self._body


def make_store(tmp: str, refresh_token: str = "R1") -> MDRTokenStore:
    return MDRTokenStore(
        str(Path(tmp) / "tokens.json"),
        api_url="https://mdr.example/api/v1",
        client_id="client",
        refresh_token=refresh_token,
        verify=False,
        retry_delay_seconds=1,
    )


class TokenRotationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_concurrent_refresh_rotates_once(self) -> None:
        store = make_store(self.tmp)
        store._access_token = jwt(-10)
        calls = []

        def fake_post(*_args, **_kwargs):
            calls.append(1)
            time.sleep(0.1)
            return FakeResponse(
                200, {"access_token": jwt(1800), "refresh_token": "R2"}
            )

        results = []
        with mock.patch("mdr_iris_sync.mdr_client.requests.post", fake_post):
            threads = [
                threading.Thread(target=lambda: results.append(store.access_token()))
                for _ in range(2)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(10)

        self.assertEqual(len(calls), 1, "session/confirm must be called exactly once")
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1])

        saved = json.loads(Path(self.tmp, "tokens.json").read_text())
        self.assertEqual(saved["refresh_token"], "R2")

    def test_reuses_pair_rotated_by_another_process(self) -> None:
        store = make_store(self.tmp)
        store._access_token = jwt(-100)
        calls = []

        # Another process already rotated the pair and saved it.
        Path(self.tmp, "tokens.json").write_text(
            json.dumps(
                {
                    "access_token": jwt(1700),
                    "refresh_token": "R2",
                    "updated_at": int(time.time()),
                }
            )
        )

        def fake_post(*_args, **_kwargs):
            calls.append(1)
            return FakeResponse(409, text="Already changed")

        with mock.patch("mdr_iris_sync.mdr_client.requests.post", fake_post):
            token = store.refresh_after_auth_error(jwt(-100))

        self.assertEqual(calls, [], "no network call when a newer pair is on disk")
        self.assertEqual(token, json.loads(Path(self.tmp, "tokens.json").read_text())["access_token"])

    def test_409_without_newer_pair_raises(self) -> None:
        store = make_store(self.tmp)
        store._access_token = jwt(-100)

        def fake_post(*_args, **_kwargs):
            return FakeResponse(409, text="Already changed")

        with mock.patch("mdr_iris_sync.mdr_client.requests.post", fake_post):
            with self.assertRaises(MDRTokenError) as ctx:
                store.force_refresh(max_attempts=1)

        self.assertEqual(ctx.exception.status_code, 409)

    def test_no_refresh_when_another_thread_already_did_it(self) -> None:
        store = make_store(self.tmp)
        store._access_token = jwt(1800)

        def fake_post(*_args, **_kwargs):
            raise AssertionError("must not refresh")

        with mock.patch("mdr_iris_sync.mdr_client.requests.post", fake_post):
            token = store.refresh_after_auth_error("stale-token")

        self.assertEqual(token, store._access_token)


if __name__ == "__main__":
    unittest.main()
