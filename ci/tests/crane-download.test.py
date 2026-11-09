# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise the manifest job's download against a controlled HTTP server."""

import io
import os
import re
import subprocess
import tarfile
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class CraneDownload(unittest.TestCase):
    def run_download(self, statuses):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w:gz") as archive:
            content = b"#!/bin/sh\necho fixture-crane\n"
            member = tarfile.TarInfo("crane")
            member.size = len(content)
            member.mode = 0o755
            archive.addfile(member, io.BytesIO(content))
        responses = iter(statuses)
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                status = next(responses, statuses[-1])
                requests.append(status)
                body = payload.getvalue() if status == 200 else b"upstream unavailable"
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        config = (Path(__file__).resolve().parents[2] / ".gitlab-ci.yml").read_text()
        block = re.search(r"(?ms)^\.crane-tools:\n(.*?)(?=^\S|\Z)", config).group(1)
        commands = [
            line.strip()[2:]
            for line in block.splitlines()
            if line.startswith(("    - curl ", "    - tar "))
        ]
        self.assertTrue(commands, "manifest job must install crane")
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                destination = work / "bin"
                destination.mkdir()
                script = "\n".join(commands)
                script = re.sub(
                    r"https://github.com/[^\s\"]+\.tar\.gz",
                    f"http://127.0.0.1:{server.server_port}/crane.tar.gz",
                    script,
                )
                script = script.replace("/usr/local/bin", str(destination))
                script = script.replace("/tmp/crane.tar.gz", str(work / "crane.tar.gz"))
                result = subprocess.run(
                    ["sh", "-ec", script],
                    capture_output=True,
                    text=True,
                    timeout=45,
                    env={**os.environ, "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"},
                )
                installed = destination / "crane"
                output = None
                if installed.exists():
                    output = subprocess.check_output([str(installed)], text=True).strip()
                return result, requests, output
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_transient_http_failures_recover_before_extraction(self):
        result, requests, output = self.run_download([503, 503, 200])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(requests, [503, 503, 200])
        self.assertEqual(output, "fixture-crane")

    def test_permanent_http_failure_never_installs_a_tool(self):
        result, _requests, output = self.run_download([503])
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(output)


if __name__ == "__main__":
    unittest.main()
