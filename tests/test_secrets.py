import math
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from configguard.scanners.secrets import (  # noqa: E402
    SecretScanner,
    Severity,
    is_placeholder,
    redact,
    shannon_entropy,
)

AWS_KEY_ID = "AKIA" + "Q3EGRKZ7X4PLM2NW"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYzq9Lm3Tv8H"
GITHUB_TOKEN = "ghp_" + "Zx81kLmQ2wErTy7UiOp3AsDfGh4JkLzXcVbN"
STRIPE_KEY = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc9Xa"
GOOGLE_KEY = "AIza" + "SyD-9tSrke72PouQMnMX7KXbsw8a1Kq4Rd0"
SLACK_TOKEN = "xoxb-" + "2041765139-8301485263-Hk3mQz9tLw2Xv7Rp"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
OPAQUE_BEARER = "9fK2mQ7xLp4Rz8Tw1Vb6Nc3Yh5Jd0Gs"
RANDOM_BASE64 = "Q2hhbmdlTWUhX3Byb2Q9a9Zx7LmP4wR"
RANDOM_HEX = "3f9a7c2e1b8d4f60a5e9c7b31d2f8e4a"


def rule_ids(findings):
    return [f.rule_id for f in findings]


class ShannonEntropyTests(unittest.TestCase):
    def test_empty_string_has_zero_entropy(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_repeated_character_has_zero_entropy(self):
        self.assertEqual(shannon_entropy("aaaaaaaa"), 0.0)

    def test_uniform_distribution_reaches_log2_of_alphabet(self):
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)
        self.assertAlmostEqual(shannon_entropy("0123456789abcdef"), math.log2(16))

    def test_random_token_is_more_entropic_than_word(self):
        self.assertGreater(shannon_entropy(RANDOM_BASE64), shannon_entropy("passwordpassword"))


class HelperTests(unittest.TestCase):
    def test_redact_hides_middle_of_secret(self):
        redacted = redact(GITHUB_TOKEN)
        self.assertTrue(redacted.startswith("ghp_"))
        self.assertNotIn(GITHUB_TOKEN[6:30], redacted)

    def test_redact_short_value(self):
        self.assertEqual(redact("abc"), "a**")

    def test_placeholders(self):
        for value in ("${DB_PASSWORD}", "<password>", "changeme", "****", "xxxx", "{{ secret }}", "$PASS", "%s"):
            with self.subTest(value=value):
                self.assertTrue(is_placeholder(value))
        self.assertFalse(is_placeholder("S3cr3t!Prod#2024"))


class ApiKeyDetectionTests(unittest.TestCase):
    def setUp(self):
        self.scanner = SecretScanner()

    def assertDetected(self, text, rule_id):
        findings = self.scanner.scan_text(text)
        self.assertIn(rule_id, rule_ids(findings), msg=f"{rule_id} não detectado em: {text!r}")
        return findings

    def test_aws_access_key_id(self):
        findings = self.assertDetected(f"aws_access_key_id = {AWS_KEY_ID}", "aws-access-key-id")
        finding = next(f for f in findings if f.rule_id == "aws-access-key-id")
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertNotIn(AWS_KEY_ID, finding.redacted_match)

    def test_aws_secret_access_key(self):
        self.assertDetected(f'AWS_SECRET_ACCESS_KEY="{AWS_SECRET}"', "aws-secret-access-key")

    def test_github_token(self):
        self.assertDetected(f"token: {GITHUB_TOKEN}", "github-token")

    def test_stripe_live_key(self):
        self.assertDetected(f"stripe.api_key = '{STRIPE_KEY}'", "stripe-secret-key")

    def test_google_api_key(self):
        self.assertDetected(f"const key = \"{GOOGLE_KEY}\";", "google-api-key")

    def test_slack_token(self):
        self.assertDetected(f"SLACK_BOT_TOKEN={SLACK_TOKEN}", "slack-token")

    def test_private_key_header(self):
        self.assertDetected("-----BEGIN RSA PRIVATE KEY-----", "private-key")
        self.assertDetected("-----BEGIN OPENSSH PRIVATE KEY-----", "private-key")

    def test_generic_api_key_assignment(self):
        self.assertDetected('API_KEY = "a8Fk29xLq0Pz"', "generic-secret-assignment")
        self.assertDetected('{"client_secret": "S3cr3t!Prod#2024"}', "generic-secret-assignment")

    def test_reports_line_and_column(self):
        findings = self.scanner.scan_text(f"first line\nkey = {AWS_KEY_ID}\n")
        finding = next(f for f in findings if f.rule_id == "aws-access-key-id")
        self.assertEqual(finding.line_number, 2)
        self.assertEqual(finding.column, 7)

    def test_specific_rule_is_not_duplicated_by_entropy(self):
        findings = self.scanner.scan_text(f"token: {GITHUB_TOKEN}")
        self.assertEqual(rule_ids(findings), ["github-token"])


class TokenDetectionTests(unittest.TestCase):
    def setUp(self):
        self.scanner = SecretScanner()

    def test_jwt(self):
        findings = self.scanner.scan_text(f"session = '{JWT}'")
        self.assertIn("jwt", rule_ids(findings))

    def test_bearer_with_jwt_reports_jwt_once(self):
        findings = self.scanner.scan_text(f"Authorization: Bearer {JWT}")
        self.assertEqual(rule_ids(findings), ["jwt"])

    def test_opaque_bearer_token(self):
        findings = self.scanner.scan_text(f'headers = {{"Authorization": "Bearer {OPAQUE_BEARER}"}}')
        self.assertIn("bearer-token", rule_ids(findings))

    def test_bearer_placeholder_is_ignored(self):
        findings = self.scanner.scan_text('curl -H "Authorization: Bearer ${ACCESS_TOKEN_FROM_VAULT}"')
        self.assertNotIn("bearer-token", rule_ids(findings))

    def test_jwt_like_prose_is_ignored(self):
        self.assertEqual(self.scanner.scan_text("eyJ is the base64 prefix of a JSON object"), [])


class DatabaseConnectionStringTests(unittest.TestCase):
    def setUp(self):
        self.scanner = SecretScanner()

    def test_url_style_connection_strings(self):
        urls = [
            "postgresql://admin:Sup3rS3cret@db.internal:5432/app",
            "mysql://root:r00tPass!@127.0.0.1/shop",
            "mongodb+srv://svc:Mng0Pa55w0rd@cluster0.abcd.mongodb.net/prod",
            "redis://default:R3d1sK3y@cache:6379/0",
            "amqp://guest:Rabb1tMQ@broker:5672/",
        ]
        for url in urls:
            with self.subTest(url=url):
                findings = self.scanner.scan_text(f'DATABASE_URL="{url}"')
                self.assertEqual(rule_ids(findings), ["database-connection-string"])
                self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_ado_net_connection_string(self):
        text = "Server=sql01;Database=erp;User Id=sa;Password=Erp#2024Prod;"
        self.assertIn("database-connection-string", rule_ids(self.scanner.scan_text(text)))

    def test_placeholder_passwords_are_ignored(self):
        for url in (
            "postgresql://user:${DB_PASSWORD}@db:5432/app",
            "mysql://user:<password>@localhost/db",
            "postgres://user:password@localhost/db",
        ):
            with self.subTest(url=url):
                self.assertEqual(self.scanner.scan_text(url), [])

    def test_url_without_credentials_is_ignored(self):
        self.assertEqual(self.scanner.scan_text("postgresql://db.internal:5432/app"), [])


class EntropyDetectionTests(unittest.TestCase):
    def setUp(self):
        self.scanner = SecretScanner()

    def test_high_entropy_base64_string(self):
        findings = self.scanner.scan_text(f'token_value = "{RANDOM_BASE64}"')
        self.assertIn("high-entropy-base64", rule_ids(findings))

    def test_high_entropy_hex_string(self):
        findings = self.scanner.scan_text(f"signing = '{RANDOM_HEX}'")
        self.assertIn("high-entropy-hex", rule_ids(findings))

    def test_entropy_can_be_disabled(self):
        scanner = SecretScanner(entropy_enabled=False)
        self.assertEqual(scanner.scan_text(f'value = "{RANDOM_BASE64}"'), [])

    def test_hash_digests_are_ignored(self):
        lines = [
            "FROM python@sha256:" + "a1b2c3d4e5f60718293a4b5c6d7e8f90" * 2,
            'integrity: "sha512-' + RANDOM_BASE64 + '"',
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(self.scanner.scan_text(line), [])


class FalsePositiveTests(unittest.TestCase):
    def setUp(self):
        self.scanner = SecretScanner()

    def test_ordinary_source_code(self):
        source = "\n".join([
            "def get_user_account_information(user_id):",
            "    password = os.environ['DB_PASSWORD']",
            "    api_key = settings.API_KEY",
            "    secret_key = get_secret_from_vault()",
            "    if password == user_input:",
            "        return SecretScannerConfiguration",
            "    api_key: Optional[str] = None",
            "    url = 'https://example.com/api/v1/users/profile/settings'",
            "    path = 'src/configguard/scanners/secrets.py'",
            "    request_id = '550e8400-e29b-41d4-a716-446655440000'",
        ])
        self.assertEqual(self.scanner.scan_text(source), [])

    def test_env_file_with_placeholders(self):
        env = "\n".join([
            "DB_PASSWORD=${DB_PASSWORD}",
            "API_KEY=<your-api-key>",
            "SECRET_KEY=changeme",
            "AUTH_TOKEN=",
        ])
        self.assertEqual(self.scanner.scan_text(env), [])

    def test_low_entropy_long_strings(self):
        self.assertEqual(self.scanner.scan_text('banner = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'), [])
        self.assertEqual(self.scanner.scan_text("checksum = 00000000000000000000000000000000"), [])

    def test_ignore_pragma(self):
        line = f"key = {AWS_KEY_ID}  # configguard:ignore"
        self.assertEqual(self.scanner.scan_text(line), [])


class FileScanningTests(unittest.TestCase):
    def setUp(self):
        self.scanner = SecretScanner()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def test_scan_file_sets_path(self):
        path = self.write("config/settings.py", f"AWS_KEY = '{AWS_KEY_ID}'\n")
        findings = self.scanner.scan_file(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].file_path, str(path))

    def test_scan_path_skips_vendor_dirs_lockfiles_and_binaries(self):
        self.write("app/.env", "DATABASE_URL=postgres://app:Pr0dPa55@db/app\n")
        self.write("node_modules/lib/index.js", f"const k = '{GITHUB_TOKEN}';\n")
        self.write(".git/config", f"token = {GITHUB_TOKEN}\n")
        self.write("package-lock.json", f'"integrity": "{RANDOM_BASE64}"\n')
        self.write("logo.png", b"\x89PNG\r\n" + AWS_KEY_ID.encode())
        self.write("data.bin.txt", b"\x00\x01" + AWS_KEY_ID.encode())

        findings = self.scanner.scan_path(self.root)

        self.assertEqual(rule_ids(findings), ["database-connection-string"])
        self.assertTrue(findings[0].file_path.endswith(".env"))

    def test_missing_file_returns_empty(self):
        self.assertEqual(self.scanner.scan_file(self.root / "missing.txt"), [])

    def test_oversized_file_is_skipped(self):
        path = self.write("big.txt", f"{AWS_KEY_ID}\n")
        self.assertEqual(SecretScanner(max_file_size=4).scan_file(path), [])

    def test_finding_serialization(self):
        finding = self.scanner.scan_text(f"k = {AWS_KEY_ID}")[0]
        data = finding.to_dict()
        self.assertEqual(data["severity"], "critical")
        self.assertEqual(data["rule_id"], "aws-access-key-id")
        self.assertNotIn(AWS_KEY_ID, str(data))


if __name__ == "__main__":
    unittest.main()
