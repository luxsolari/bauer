"""Offline, stdlib-only tests for the opt-in evidence adapter."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "skills/bauer/scripts/jev.py"


def load_adapter():
    assert SCRIPT.is_file(), "Jev adapter must exist"
    spec = importlib.util.spec_from_file_location("bauer_jev", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class JevTests(unittest.TestCase):
    def setUp(self):
        self.jev = load_adapter()

    def run_cli(self, args, key="offline-test-key"):
        output = io.StringIO()
        with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": key}, clear=True):
            with contextlib.redirect_stdout(output):
                code = self.jev.main(args)
        return code, json.loads(output.getvalue())

    def packet_cli(self, packet=None, key="offline-test-key", raw=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.json"
            path.write_bytes(raw if raw is not None else json.dumps(
                packet if packet is not None else {"claim": "Input reaches sink"}
            ).encode("utf-8"))
            return self.run_cli([str(path), "--allow-external", "--packet-reviewed"], key)

    def test_missing_key_returns_unavailable_without_network(self):
        with mock.patch("urllib.request.build_opener") as network:
            code, result = self.packet_cli(key="")
        self.assertNotEqual(code, 0)
        self.assertEqual(result["reason"], "missing_api_key")
        network.assert_not_called()

    @staticmethod
    def valid_response():
        return {
            "model": "jev-1.13.0",
            "answers": {
                "attacker_control": {"type": "noul", "noul": 0.8},
                "missing_context": {"type": "noul", "noul": 0.3},
                "control_effectiveness": {
                    "type": "choice", "choice": "insufficient_evidence",
                    "probabilities": {"effective": 0.1, "ineffective": 0.2,
                                      "insufficient_evidence": 0.7},
                    "confidence": 0.4,
                },
            },
            "usage": {"input_tokens": 300, "output_tokens": 30},
        }

    def test_curated_packet_produces_pinned_review_with_request_hash(self):
        import hashlib
        response = self.valid_response()
        with mock.patch("urllib.request.build_opener") as factory:
            stream = factory.return_value.open.return_value.__enter__.return_value
            stream.read.return_value = json.dumps(response).encode()
            stream.status = 200
            code, result = self.packet_cli({"claim": "Input reaches sink",
                                            "code_context": ["sink(value)"],
                                            "missing_context": "https://example.invalid/not-fetched"})
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "available")
        self.assertTrue(result["review_only"])
        self.assertEqual(result["answers"], response["answers"])
        self.assertEqual(result["model"], response["model"])
        self.assertEqual(result["usage"], response["usage"])
        self.assertEqual(result["rubric_version"], "bauer-jev-evidence-v1")
        self.assertNotIn("Input reaches sink", json.dumps(result))
        request = factory.return_value.open.call_args.args[0]
        self.assertEqual(factory.return_value.open.call_args.kwargs, {"timeout": 20})
        self.assertEqual(request.full_url, "https://api.typesafe.ai/v1/systemone")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Authorization"), "Bearer offline-test-key")
        self.assertEqual(result["request_sha256"], hashlib.sha256(request.data).hexdigest())
        payload = json.loads(request.data)
        self.assertEqual(payload['state']['code_context'], ['sink(value)'])
        self.assertEqual(payload["model"], "jev-1.13.0")
        questions = payload["questions"]
        self.assertEqual(set(questions), set(response["answers"]))
        self.assertEqual(questions["attacker_control"]["type"], "noul")
        self.assertEqual(questions["missing_context"]["type"], "noul")
        self.assertEqual(set(questions["control_effectiveness"]["criteria"]),
                         {"effective", "ineffective", "insufficient_evidence"})
        for question in questions.values():
            self.assertIn("hostile", question["instructions"].lower())
            self.assertIn("instructions", question)
            self.assertIn("criteria", question)
        self.assertIn("concentration", result["limitations"])
        self.assertIn("accuracy", result["limitations"])
        stream.read.assert_called_once_with(256 * 1024 + 1)

    def test_invalid_packets_are_rejected_before_network(self):
        invalid = [
            b"not json", b'[]', b'{}', b'{"claim": ""}',
            b'{"claim": "x", "files": ["secret.py"]}',
            b'{"claim": 1}', b'{"claim": [1]}', b'{"claim": {"nested": "x"}}',
            b'{"claim":"x","claim":"y"}', b'{"claim":"x","controls":NaN}',
            b'\xff', json.dumps({"claim": "x" * 8193}).encode(),
            json.dumps({"claim": "x", "controls": ["ok"] * 65}).encode(),
            json.dumps({"claim": "x", "controls": ["x" * 8193]}).encode(),
            json.dumps({"claim": "x", "controls": "é" * 8192,
                        "test_evidence": "é" * 8192}).encode(),
            json.dumps({"claim": "x"}).encode() + b" " * 32768,
        ]
        with mock.patch("urllib.request.build_opener") as network:
            for raw in invalid:
                with self.subTest(raw=raw[:60]):
                    code, result = self.packet_cli(raw=raw)
                    self.assertNotEqual(code, 0)
                    self.assertEqual(result["reason"], "invalid_packet")
                    self.assertNotIn("answers", result)
            network.assert_not_called()
            code, result = self.run_cli(["/nonexistent/packet.json", "--allow-external", "--packet-reviewed"])
            self.assertNotEqual(code, 0)
            self.assertEqual(result["reason"], "invalid_packet")

    def test_common_secrets_are_blocked_without_echoing_them(self):
        secrets = [
            "xoxb-" + "1234567890-" * 2 + "abcdefghijklmnop",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop",
            "glpat-" + "A" * 20,
            "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----",
            "ghp_" + "A" * 36, "github_pat_" + "A" * 40,
            "sk-proj-" + "A" * 30, "AKIA" + "A" * 16,
            "Bearer abcdefghijklmnop", "password = 'hunter2'",
            '"api_key": "literal-secret"', "TYPESAFE_API_KEY=literal-secret",
            "token: literal-secret", "secret = 'literal-secret'",
            "https://user:password@example.invalid/path",
        ]
        with mock.patch("urllib.request.build_opener") as network:
            for secret in secrets:
                with self.subTest(secret=secret):
                    code, result = self.packet_cli({"claim": "Input reaches sink", "code_context": [secret]})
                    self.assertNotEqual(code, 0)
                    self.assertEqual(result["reason"], "secret_detected")
                    self.assertNotIn(secret, json.dumps(result))
            network.assert_not_called()

    def response_cli(self, raw, status=200):
        with mock.patch("urllib.request.build_opener") as factory:
            stream = factory.return_value.open.return_value.__enter__.return_value
            stream.read.return_value = raw
            stream.status = status
            outcome = self.packet_cli()
            factory.return_value.open.assert_called_once()
            return outcome

    def test_untrusted_response_schema_is_validated_completely(self):
        import copy
        invalid = [None, [], {}, {"model": "jev-latest"}]
        changes = [
            (("model",), "jev-latest"),
            (("answers",), {}), (("answers", "unexpected"), {}),
            (("answers", "attacker_control", "type"), "choice"),
            (("answers", "attacker_control", "noul"), True),
            (("answers", "attacker_control", "noul"), -0.1),
            (("answers", "attacker_control", "noul"), 1.1),
            (("answers", "attacker_control", "noul"), float("nan")),
            (("answers", "missing_context", "noul"), "0.5"),
            (("answers", "missing_context", "noul"), float("inf")),
            (("answers", "missing_context", "extra"), "echo packet"),
            (("answers", "control_effectiveness", "type"), "noul"),
            (("answers", "control_effectiveness", "choice"), "unknown"),
            (("answers", "control_effectiveness", "choice"), "effective"),
            (("answers", "control_effectiveness", "probabilities"), {"effective": 1}),
            (("answers", "control_effectiveness", "probabilities", "extra"), 0),
            (("answers", "control_effectiveness", "probabilities", "effective"), True),
            (("answers", "control_effectiveness", "probabilities", "effective"), -0.1),
            (("answers", "control_effectiveness", "probabilities", "effective"), 1.1),
            (("answers", "control_effectiveness", "probabilities", "effective"), 0.2),
            (("answers", "control_effectiveness", "confidence"), float("nan")),
            (("answers", "control_effectiveness", "confidence"), True),
            (("answers", "control_effectiveness", "confidence"), 1.1),
            (("usage",), None), (("usage",), {}),
            (("usage", "input_tokens"), -1), (("usage", "input_tokens"), True),
            (("usage", "output_tokens"), 0.5),
            (("usage", "output_tokens"), 10 ** 12),
            (("usage", "extra"), "echo packet"), (("extra",), "echo packet"),
        ]
        for path, value in changes:
            response = copy.deepcopy(self.valid_response())
            target = response
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            invalid.append(response)
        response = self.valid_response()
        del response["answers"]["control_effectiveness"]["confidence"]
        invalid.append(response)
        for index, response in enumerate(invalid):
            with self.subTest(case=index):
                code, result = self.response_cli(json.dumps(response).encode())
                self.assertNotEqual(code, 0)
                self.assertEqual(result["reason"], "invalid_response")
                self.assertNotIn("answers", result)
                self.assertNotIn("echo packet", json.dumps(result))

    def test_malformed_or_oversized_response_is_unavailable(self):
        valid = json.dumps(self.valid_response()).encode()
        cases = [b"not json", b"\xff", b"[" * 10000,
                 valid[:-1] + b',"model":"jev-1.13.0"}',
                 valid + b" " * (256 * 1024 + 1 - len(valid))]
        for raw in cases:
            with self.subTest(size=len(raw)):
                code, result = self.response_cli(raw)
                self.assertNotEqual(code, 0)
                self.assertEqual(result["reason"], "invalid_response")

    def test_transport_failures_never_leak_details_or_retry(self):
        import urllib.error
        import http.client
        failures = [
            http.client.IncompleteRead(b"PRIVATE BODY"),
            urllib.error.HTTPError("https://evil.invalid", 401,
                                   "offline-test-key PRIVATE BODY", {}, io.BytesIO(b"PRIVATE BODY")),
            urllib.error.URLError("offline-test-key PRIVATE BODY"),
            TimeoutError("offline-test-key PRIVATE BODY"),
            OSError("offline-test-key PRIVATE BODY"),
        ]
        for failure in failures:
            with self.subTest(kind=type(failure).__name__):
                with mock.patch("urllib.request.build_opener") as factory:
                    factory.return_value.open.side_effect = failure
                    code, result = self.packet_cli()
                    factory.return_value.open.assert_called_once()
                self.assertNotEqual(code, 0)
                self.assertEqual(result["reason"], "transport_error")
                self.assertNotIn("offline-test-key", json.dumps(result))
                self.assertNotIn("PRIVATE BODY", json.dumps(result))
        with mock.patch("urllib.request.build_opener") as factory:
            stream = factory.return_value.open.return_value.__enter__.return_value
            stream.status = 200
            stream.read.side_effect = TimeoutError("PRIVATE BODY")
            code, result = self.packet_cli()
        self.assertNotEqual(code, 0)
        self.assertEqual(result["reason"], "transport_error")

    def test_redirects_are_rejected_by_real_opener_without_forwarding_bearer(self):
        import email.message
        import urllib.request
        import urllib.response
        real_build_opener = urllib.request.build_opener
        requests = []

        class FakeHTTPS(urllib.request.HTTPSHandler):
            def https_open(self, request):
                requests.append(request)
                headers = email.message.Message()
                headers["Location"] = "https://evil.invalid/collect"
                response = urllib.response.addinfourl(io.BytesIO(b"PRIVATE BODY"), headers,
                                                     request.full_url, redirect_status)
                response.msg = "Redirect"
                return response

        for redirect_status in (301, 302, 303, 307, 308):
            requests.clear()
            with self.subTest(status=redirect_status):
                with mock.patch("urllib.request.build_opener",
                                side_effect=lambda *handlers: real_build_opener(FakeHTTPS(), *handlers)):
                    code, result = self.packet_cli()
                self.assertNotEqual(code, 0)
                self.assertEqual(result["reason"], "transport_error")
                self.assertEqual(len(requests), 1)
                self.assertEqual(requests[0].full_url, "https://api.typesafe.ai/v1/systemone")
                self.assertNotIn("PRIVATE BODY", json.dumps(result))

    def test_non_success_http_status_is_unavailable_without_body_read(self):
        for status in (201, 204, 301, 400, 429, 500):
            with self.subTest(status=status):
                with mock.patch("urllib.request.build_opener") as factory:
                    stream = factory.return_value.open.return_value.__enter__.return_value
                    stream.status = status
                    stream.read.return_value = json.dumps(self.valid_response()).encode()
                    code, result = self.packet_cli()
                    stream.read.assert_not_called()
                self.assertNotEqual(code, 0)
                self.assertEqual(result["reason"], "transport_error")

    def test_invalid_cli_arguments_return_safe_json(self):
        for args in ([], ["packet.json", "--unknown=PRIVATE BODY"]):
            with self.subTest(args=args):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    code, result = self.run_cli(args)
                self.assertNotEqual(code, 0)
                self.assertEqual(result["reason"], "invalid_arguments")
                self.assertEqual(stderr.getvalue(), "")
                self.assertNotIn("PRIVATE BODY", json.dumps(result))

    def test_both_consent_flags_are_required_before_network(self):
        with mock.patch("urllib.request.build_opener") as network:
            for flags in ([], ["--allow-external"], ["--packet-reviewed"]):
                with self.subTest(flags=flags):
                    code, result = self.run_cli(["missing.json"] + flags)
                    self.assertNotEqual(code, 0)
                    self.assertEqual(result["status"], "unavailable")
                    self.assertEqual(result["reason"], "consent_required")
                    self.assertTrue(result["review_only"])
            network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
