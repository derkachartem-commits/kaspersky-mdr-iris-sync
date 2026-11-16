import copy
import unittest

from mdr_iris_sync import mapping
from mdr_iris_sync.config import DEFAULTS
from mdr_iris_sync.proxy import proxies_for_url, resolve_proxy_config


class MappingTests(unittest.TestCase):
    def test_epoch_ms_to_iso(self):
        self.assertEqual(mapping.epoch_ms_to_iso(0), "1970-01-01T00:00:00Z")
        self.assertEqual(mapping.epoch_ms_to_iso(1700000000000), "2023-11-14T22:13:20Z")
        self.assertIsNone(mapping.epoch_ms_to_iso(None))
        self.assertIsNone(mapping.epoch_ms_to_iso("not-a-number"))

    def test_priority_to_severity(self):
        self.assertEqual(mapping.priority_to_severity("LOW"), 4)
        self.assertEqual(mapping.priority_to_severity("HIGH"), 5)
        self.assertEqual(mapping.priority_to_severity("CRITICAL"), 6)
        self.assertEqual(mapping.priority_to_severity("unknown"), 2)

    def test_status_mapping_default(self):
        statuses = {"new": 1, "closed": 3}
        self.assertEqual(mapping.status_to_alert_status("New", statuses, 9), 1)
        self.assertEqual(mapping.status_to_alert_status("Closed", statuses, 9), 3)
        self.assertEqual(mapping.status_to_alert_status("Whatever", statuses, 9), 9)

    def test_affected_hosts_dedupe(self):
        incident = {
            "affected_hosts_mappings": [
                {"host_id": "1", "host_name": "PC-1"},
                {"host_id": "2", "host_name": "PC-1"},
            ],
            "affected_hosts": ["PC-2", {"host_name": "PC-3", "host_id": "3"}],
        }
        hosts = mapping.affected_hosts(incident)
        self.assertEqual([host["name"] for host in hosts], ["PC-1", "PC-2", "PC-3"])

    def test_build_alert_payload(self):
        cfg = copy.deepcopy(DEFAULTS)
        cfg["iris"]["customer_id"] = 7
        cfg["iris"]["classification_id"] = 4
        incident = {
            "incident_id": "abc123",
            "incident_number": 42,
            "summary": "Suspicious PowerShell",
            "description": "Details",
            "priority": "HIGH",
            "status": "New",
            "creation_time": 1700000000000,
            "tenant_name": "ACME",
            "affected_hosts_mappings": [{"host_id": "h1", "host_name": "PC-1"}],
            "mitre_tactics": ["Execution"],
            "mitre_techniques": ["T1059"],
        }
        payload = mapping.build_alert_payload(incident, cfg)
        self.assertEqual(payload["alert_customer_id"], 7)
        self.assertEqual(payload["alert_classification_id"], 7)
        self.assertEqual(payload["alert_severity_id"], 5)
        self.assertIsNone(payload["alert_owner_id"])
        self.assertEqual(payload["alert_status_id"], 2)
        self.assertIn("#42", payload["alert_title"])
        self.assertIn("PC-1", payload["alert_description"])
        self.assertEqual(payload["alert_source_ref"], "abc123")
        self.assertEqual(payload["alert_assets"][0]["asset_name"], "PC-1")
        self.assertEqual(payload["alert_source_event_time"], "2023-11-14T22:13:20Z")

    def test_comment_extractors(self):
        iris_comment = {
            "comment_id": 5,
            "comment_text": "hello",
            "comment_author": "analyst",
            "comment_date": "2026-11-16T10:00:00",
        }
        self.assertEqual(mapping.comment_id(iris_comment), "5")
        self.assertEqual(mapping.comment_text(iris_comment), "hello")
        self.assertEqual(mapping.comment_author(iris_comment), "analyst")

        mdr_comment = {
            "comment_id": "c1",
            "text": "world",
            "author_name": "MDR Team",
            "creation_time": 1700000000000,
        }
        self.assertEqual(mapping.comment_id(mdr_comment), "c1")
        self.assertEqual(mapping.comment_text(mdr_comment), "world")
        self.assertEqual(mapping.comment_author(mdr_comment), "MDR Team")
        self.assertIn("2023-11-14", mapping.comment_created(mdr_comment))

    def test_case_status_v2_and_v3(self):
        self.assertEqual(mapping.case_status_id({"status_id": 3}), 3)
        self.assertEqual(mapping.case_status_id({"state_id": 4}), 4)
        self.assertEqual(mapping.case_status_id({"state": {"state_id": 5}}), 5)
        self.assertTrue(mapping.case_is_closed({"state_id": 3}, 3))
        self.assertTrue(mapping.case_is_closed({"close_date": "2026-11-16"}, 99))
        self.assertFalse(mapping.case_is_closed({"state_id": 2}, 3))

    def test_fingerprint_ignores_whitespace_and_case(self):
        self.assertEqual(
            mapping.fingerprint("Hello   World"),
            mapping.fingerprint("hello world"),
        )


class ProxyTests(unittest.TestCase):
    def test_global_proxy(self):
        cfg = {"enabled": True, "url": "http://127.0.0.1:10808", "no_proxy": []}
        resolved = resolve_proxy_config(cfg)
        self.assertEqual(resolved["http"], "http://127.0.0.1:10808")
        self.assertEqual(resolved["https"], "http://127.0.0.1:10808")
        proxies = proxies_for_url(resolved, "https://mdr.kaspersky.com")
        self.assertEqual(proxies["https"], "http://127.0.0.1:10808")

    def test_proxy_credentials(self):
        cfg = {
            "enabled": True,
            "url": "http://proxy.corp.local:3128",
            "username": "svc@corp",
            "password": "p@ss word",
        }
        resolved = resolve_proxy_config(cfg)
        self.assertEqual(
            resolved["https"],
            "http://svc%40corp:p%40ss%20word@proxy.corp.local:3128",
        )

    def test_service_override_and_disable(self):
        base = {"enabled": True, "url": "http://127.0.0.1:10808"}
        override = resolve_proxy_config(base, {"url": "socks5h://127.0.0.1:1080"})
        self.assertEqual(override["https"], "socks5h://127.0.0.1:1080")
        self.assertIsNone(resolve_proxy_config(base, False))
        self.assertIsNone(resolve_proxy_config({"enabled": False, "url": "x"}))

    def test_no_proxy_bypass(self):
        cfg = {
            "enabled": True,
            "url": "http://127.0.0.1:10808",
            "no_proxy": ["127.0.0.1", "localhost"],
        }
        resolved = resolve_proxy_config(cfg)
        self.assertIsNone(proxies_for_url(resolved, "https://127.0.0.1:8445/api/v2/me"))
        self.assertIsNotNone(proxies_for_url(resolved, "https://mdr.kaspersky.com"))


if __name__ == "__main__":
    unittest.main()
