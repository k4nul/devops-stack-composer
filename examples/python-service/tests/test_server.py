from __future__ import annotations

import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

from app.server import create_server


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_server("127.0.0.1", 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def response(self, path: str) -> tuple[int, dict[str, str]]:
        try:
            response = urlopen(self.base_url + path, timeout=2)
        except HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read())

    def test_health(self) -> None:
        self.assertEqual(self.response("/health"), (200, {"status": "healthy"}))

    def test_readiness(self) -> None:
        self.assertEqual(self.response("/ready"), (200, {"status": "ready"}))

    def test_unknown_path(self) -> None:
        self.assertEqual(self.response("/missing"), (404, {"error": "not found"}))


if __name__ == "__main__":
    unittest.main()
