"""Tests for the safety-critical parts of diag-agent and jobwatch. Standard library only:
    python -m unittest discover -s tests -v
"""
import datetime as dt
import importlib.util
import json
import os
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(path):
    with open(path) as f:
        return f.read()


def put(path, text):
    with open(path, "w") as f:
        f.write(text)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


agent = load("diag_agent", "diag-agent.py")
jobwatch = load("jobwatch", "jobwatch/jobwatch.py")


class Redaction(unittest.TestCase):
    def test_secrets_are_removed(self):
        cases = {
            "Authorization: Bearer abc.def.ghi": "abc.def.ghi",
            "api_key=sk-live-1234567890": "sk-live-1234567890",
            'password: "hunter2"': "hunter2",
            "token = 0123456789abcdef0123456789abcdef": "0123456789abcdef0123456789abcdef",
            "key sk-ant-api03-AbCdEf_123": "sk-ant-api03-AbCdEf_123",
            "push https://ntfy.sh/my-secret-topic": "my-secret-topic",
            "GET https://example.com/hook?sig=abc123&x=1": "sig=abc123",
            "mail from someone@example.org failed": "someone@example.org",
            "blob QWxhZGRpbjpvcGVuIHNlc2FtZQAAAAAAAAAAAAAAAAAAAAAAAA== end": "QWxhZGRpbjpvcGVuIHNlc2FtZQ",
        }
        for text, secret in cases.items():
            with self.subTest(text=text):
                self.assertNotIn(secret, agent.redact(text))

    def test_normal_log_lines_survive(self):
        line = "2026-10-27 12:00 paperless-webserver-1 exited with code 137 (OOM)"
        self.assertEqual(agent.redact(line), line)


class Validation(unittest.TestCase):
    def good(self, **kw):
        d = {"title": "Paperless down", "summary_en": "OOM kill.", "likely_cause": "memory", "confidence": "high",
             "fix_commands": ["docker compose up -d"], "risk_notes_en": "", "needs_human": True}
        d.update(kw)
        return d

    def test_accepts_schema(self):
        self.assertIsNotNone(agent.valid(self.good()))

    def test_rejects_bad_shapes(self):
        self.assertIsNone(agent.valid({"title": "x"}))
        self.assertIsNone(agent.valid(self.good(confidence="certain")))
        self.assertIsNone(agent.valid(self.good(fix_commands="rm -rf /")))
        self.assertIsNone(agent.valid("not a dict"))

    def test_dangerous_commands_are_dropped(self):
        bad = ["rm -rf /var/lib/docker", "docker system prune -af", "sudo umount /mnt/hdd", "sudo mount -a",
               "e2fsck -y /dev/sda1", "mkfs.ext4 /dev/sda1", "dd if=/dev/zero of=/dev/sda", "cat /home/pi/paperless/.env",
               "chmod -R 777 /", "sudo cat /etc/diag/claude.env"]
        safe = ["docker logs --tail 50 paperless-webserver-1", "systemctl status unbound"]
        out = agent.valid(self.good(fix_commands=bad + safe))
        self.assertEqual(out["fix_commands"], safe)

    def test_at_most_six_commands(self):
        out = agent.valid(self.good(fix_commands=[f"echo {i}" for i in range(10)]))
        self.assertEqual(len(out["fix_commands"]), 6)


class Collector(unittest.TestCase):
    def test_config_cannot_inject_commands(self):
        calls = []
        with mock.patch.object(agent, "run", side_effect=lambda argv, tail=None: calls.append(argv) or "ok"), \
             mock.patch.object(agent, "check_resolv", return_value="nameserver 1.1.1.1"):
            cfg = {"X": {"containers": ["good-1", "x; rm -rf /", "$(reboot)"], "units": ["ok.service", "a b"],
                         "checks": [{"type": "shell", "args": ["rm -rf /"]}]}}
            agent.collect("X", cfg)
        flat = [" ".join(a) for a in calls]
        self.assertTrue(any("good-1" in c for c in flat))
        self.assertTrue(any("ok.service" in c for c in flat))
        for evil in ("rm -rf", "reboot", "a b"):
            self.assertFalse(any(evil in c for c in flat), evil)

    def test_evidence_is_redacted_and_capped(self):
        noisy = "token=supersecretvalue123\n" + "x" * 100_000
        with mock.patch.object(agent, "run", return_value=noisy), mock.patch.object(agent, "check_resolv", return_value=""):
            ev = agent.collect("unknown", {}, lenient=True)
        self.assertNotIn("supersecretvalue123", ev)
        self.assertLessEqual(len(ev), agent.MAX_EVIDENCE + 100)

    def test_unknown_monitor_strict(self):
        with self.assertRaises(SystemExit):
            agent.collect("nope", {})

    def test_problems_filter(self):
        text = "all good\nERROR disk full\nstarting\nconnection refused\n"
        self.assertEqual(agent.problems(text), "ERROR disk full\nconnection refused")


class Reports(unittest.TestCase):
    def test_page_is_escaped_and_old_pages_pruned(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(agent, "SITE", d):
            old = dt.datetime.now() - dt.timedelta(days=agent.KEEP_DAYS + 5)
            agent.write_report("Old", "", "e", None, old)
            d1 = {"title": "<script>x</script>", "summary_en": "s", "likely_cause": "c", "confidence": "low",
                  "fix_commands": ["echo <b>"], "risk_notes_en": "", "needs_human": True, "_engine": "gemini"}
            agent.write_report("New <i>", "msg", "evidence <tag>", d1, dt.datetime.now())
            pages = [f for f in os.listdir(d) if f.endswith(".html") and f != "index.html"]
            self.assertEqual(len(pages), 1, "the 95-day-old page should be pruned")
            html = read(os.path.join(d, pages[0]))
            self.assertNotIn("<script>x</script>", html)
            self.assertIn("&lt;script&gt;", html)
            items = json.loads(read(os.path.join(d, "incidents.json")))
            self.assertEqual([i["monitor"] for i in items], ["New <i>"])


class JobWatch(unittest.TestCase):
    def test_late_jobs(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(jobwatch, "JOBS", d):
            now = time.time()
            put(os.path.join(d, "fresh.ok"), f"{int(now - 60)} 3600")
            put(os.path.join(d, "stale.ok"), f"{int(now - 7300)} 3600")
            put(os.path.join(d, "broken.ok"), "garbage")
            late = jobwatch.late_jobs(now)
        self.assertEqual(len(late), 1)
        self.assertTrue(late[0].startswith("stale "))


if __name__ == "__main__":
    unittest.main()
