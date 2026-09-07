"""AWS workload-identity enrollment: SigV4 signing + credential resolution.

The signature must be a real SigV4 (checked against the AWS documentation
signing-key vector) and must fold the control-plane binding headers into
SignedHeaders, otherwise the control plane rejects the request as replayable.
"""
import datetime as dt
import io
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from prismor.runtime.enterprise import aws_identity as aws
from prismor.runtime.enterprise import identity as ident

AWS_ENV = (
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
    "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_REGION", "AWS_DEFAULT_REGION",
    "PRISMOR_HOME", "PRISMOR_AGENT_KEY",
)


def _offline(*a, **k):
    raise urllib.error.URLError("offline")


class TestSigV4(unittest.TestCase):
    def test_signing_key_matches_aws_docs_vector(self):
        key = aws.signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam")
        self.assertEqual(key.hex(), "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9")

    def test_signed_request_shape_and_binding_headers(self):
        now = dt.datetime(2026, 9, 5, 12, 0, 0, tzinfo=dt.timezone.utc)
        creds = {"access_key": "AKIAEXAMPLE", "secret_key": "secret", "token": "tok"}
        req = aws.sign_get_caller_identity(creds, None, "www.prismor.dev", "orgA", now=now)
        self.assertEqual(req["method"], "POST")
        self.assertEqual(req["url"], "https://sts.amazonaws.com/")
        self.assertEqual(req["body"], aws.STS_BODY)
        h = req["headers"]
        self.assertEqual(h["X-Amz-Date"], "20260905T120000Z")
        self.assertEqual(h["X-Prismor-Org"], "orgA")
        self.assertEqual(h["X-Prismor-Server-Id"], "www.prismor.dev")
        self.assertEqual(h["X-Amz-Security-Token"], "tok")
        auth = h["Authorization"]
        self.assertIn("Credential=AKIAEXAMPLE/20260905/us-east-1/sts/aws4_request", auth)
        self.assertIn(
            "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-prismor-org;x-prismor-server-id",
            auth,
        )
        self.assertRegex(auth, r"Signature=[0-9a-f]{64}$")

    def test_signature_is_deterministic_and_binding_sensitive(self):
        now = dt.datetime(2026, 9, 5, 12, 0, 0, tzinfo=dt.timezone.utc)
        creds = {"access_key": "AKIA", "secret_key": "s", "token": ""}
        a = aws.sign_get_caller_identity(creds, "eu-west-1", "h", "orgA", now=now)
        b = aws.sign_get_caller_identity(creds, "eu-west-1", "h", "orgA", now=now)
        c = aws.sign_get_caller_identity(creds, "eu-west-1", "h", "orgB", now=now)
        self.assertEqual(a["headers"]["Authorization"], b["headers"]["Authorization"])
        self.assertNotEqual(a["headers"]["Authorization"], c["headers"]["Authorization"])
        self.assertEqual(a["url"], "https://sts.eu-west-1.amazonaws.com/")
        self.assertNotIn("X-Amz-Security-Token", a["headers"])


class TestCredentialResolution(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in AWS_ENV}
        for k in AWS_ENV:
            os.environ.pop(k, None)
        self.home = Path(tempfile.mkdtemp(prefix="prismor-aws-"))
        os.environ["PRISMOR_HOME"] = str(self.home)
        os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(self.home / "nope")

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_env_wins(self):
        os.environ["AWS_ACCESS_KEY_ID"] = "AKIA1"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "s1"
        self.assertEqual(aws.resolve_credentials(), {"access_key": "AKIA1", "secret_key": "s1", "token": ""})

    def test_profile_file(self):
        f = self.home / "creds"
        f.write_text("[default]\naws_access_key_id = AKIAP\naws_secret_access_key = sp\n", encoding="utf-8")
        os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(f)
        with mock.patch.object(urllib.request, "urlopen", _offline):
            self.assertEqual(aws.resolve_credentials()["access_key"], "AKIAP")

    def test_none_when_nothing_available(self):
        with mock.patch.object(urllib.request, "urlopen", _offline):
            self.assertIsNone(aws.resolve_credentials())

    def test_enroll_aws_posts_signed_request_and_saves_identity(self):
        os.environ["AWS_ACCESS_KEY_ID"] = "AKIA1"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "s1"
        seen = {}

        class _Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=0):
            seen["url"] = req.full_url
            seen["payload"] = json.loads(req.data.decode("utf-8"))
            return _Resp(json.dumps({
                "device_id": "d1", "org_id": "orgA", "user_id": "admin", "device_key": "prism_agent_x", "org_name": "Acme",
            }).encode("utf-8"))

        with mock.patch.object(urllib.request, "urlopen", fake_urlopen):
            rec = ident.enroll_aws("orgA", base="https://cp.example", label="task-1")
        self.assertEqual(seen["url"], "https://cp.example/api/devices/enroll/aws")
        signed = seen["payload"]["aws"]
        self.assertEqual(signed["headers"]["X-Prismor-Server-Id"], "cp.example")
        self.assertEqual(signed["headers"]["X-Prismor-Org"], "orgA")
        self.assertEqual(seen["payload"]["label"], "task-1")
        self.assertEqual(rec["source"], "aws")
        # Read the file directly: other suites monkeypatch load_identity at module level.
        saved = json.loads((self.home / "identity.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["device_key"], "prism_agent_x")
        self.assertEqual(saved["source"], "aws")

    def test_enroll_aws_without_credentials_is_a_clear_error(self):
        with mock.patch.object(urllib.request, "urlopen", _offline):
            with self.assertRaises(RuntimeError) as cm:
                ident.enroll_aws("orgA", base="https://cp.example")
        self.assertIn("no AWS credentials", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
