"""DNS tunnel detection tests."""

from __future__ import annotations

import base64
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cagesight.demo import generate_pcap  # noqa: E402
from cagesight.detectors.dns import base_domain  # noqa: E402
from cagesight.parsers import pcap  # noqa: E402
from tests.helpers import BASE_TS, event, rule_ids, run  # noqa: E402


def tunnel_events(count: int = 25) -> list:
    events = []
    for index in range(count):
        chunk = base64.b32encode(("loot-block-%03d-0123456789abcdef" % index).encode()).decode().rstrip("=")
        events.append(
            event(
                ts=BASE_TS + index,
                kind="dns",
                domain="%s.exfil-c2.net" % chunk.lower(),
                qtype="TXT",
                dst_ip="8.8.8.8",
                dst_port=53,
            )
        )
    return events


class DnsTunnelTest(unittest.TestCase):
    def test_encoded_labels_are_detected(self):
        ids = rule_ids(run(tunnel_events()))
        self.assertIn("CS-DNS-001", ids)
        self.assertIn("CS-DNS-003", ids)

    def test_high_rate_and_unique_subdomains(self):
        ids = rule_ids(run(tunnel_events(30)))
        self.assertIn("CS-DNS-002", ids)
        self.assertIn("CS-DNS-004", ids)

    def test_allowlisted_domain_is_ignored(self):
        events = [
            event(ts=BASE_TS + i, kind="dns", domain="pypi.org", qtype="A", dst_ip="8.8.8.8", dst_port=53)
            for i in range(40)
        ]
        self.assertEqual(rule_ids(run(events)), set())

    def test_short_labels_are_not_flagged(self):
        events = [
            event(ts=BASE_TS + i, kind="dns", domain="www.example.com", qtype="A", dst_ip="8.8.8.8", dst_port=53)
            for i in range(5)
        ]
        self.assertNotIn("CS-DNS-001", rule_ids(run(events)))


class DnsBaseDomainTest(unittest.TestCase):
    def test_multi_label_public_suffix(self):
        self.assertEqual(base_domain("a1.example.com.br"), "example.com.br")
        self.assertEqual(base_domain("a1.example.co.uk"), "example.co.uk")
        self.assertEqual(base_domain("a1.example.com"), "example.com")

    def test_short_label_flood_is_not_a_tunnel(self):
        # 25 个不同主机名、短标签、低熵：不应仅因为“查询多且唯一”就报隧道。
        events = [
            event(ts=BASE_TS + i * 0.5, kind="dns", domain="host%02d.example.com.br" % i,
                  qtype="A", dst_ip="8.8.8.8", dst_port=53)
            for i in range(25)
        ]
        ids = rule_ids(run(events))
        self.assertNotIn("CS-DNS-002", ids)
        self.assertNotIn("CS-DNS-004", ids)


class DnsPerformanceTest(unittest.TestCase):
    def test_window_stays_linear(self):
        # 回归测试：窗口内唯一域名统计曾是 O(n^2)，5000 个事件会卡住。
        events = []
        for index in range(5000):
            chunk = base64.b32encode(("payload-%05d-0123456789abcdef" % index).encode()).decode().rstrip("=")
            events.append(
                event(ts=BASE_TS + index * 0.01, kind="dns", domain="%s.exfil-c2.net" % chunk.lower(),
                      qtype="TXT", dst_ip="8.8.8.8", dst_port=53)
            )
        start = time.time()
        result = run(events)
        elapsed = time.time() - start
        self.assertIn("CS-DNS-002", rule_ids(result))
        self.assertLess(elapsed, 3.0, "DNS 窗口检测耗时 %.2fs，疑似退化为 O(n^2)" % elapsed)


class PcapDnsTest(unittest.TestCase):
    def test_pcap_roundtrip(self):
        import tempfile

        blob = generate_pcap()
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        try:
            handle.write(blob)
            handle.close()
            events = pcap.parse_pcap(handle.name)
        finally:
            os.unlink(handle.name)

        self.assertTrue(events)
        tunnel = [e for e in events if e.kind == "dns" and "exfil-c2.net" in e.domain]
        self.assertGreaterEqual(len(tunnel), 10)
        self.assertEqual(tunnel[0].qtype, "TXT")

        findings = run(events)
        self.assertIn("CS-DNS-001", rule_ids(findings))

    def test_https_sni_is_parsed(self):
        import tempfile

        from tests.helpers import build_pcap, ethernet, ipv4, tcp, tls_client_hello

        frame = ethernet(ipv4("172.17.0.2", "45.77.12.9", 6, tcp(50111, 443, tls_client_hello("drop.exfil-c2.net"))))
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        try:
            handle.write(build_pcap([frame]))
            handle.close()
            events = pcap.parse_pcap(handle.name)
        finally:
            os.unlink(handle.name)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].domain, "drop.exfil-c2.net")

    def test_dns_response_is_ignored(self):
        import tempfile

        from tests.helpers import build_pcap, dns_query, ethernet, ipv4, udp

        query = ethernet(
            ipv4("172.17.0.2", "8.8.8.8", 17, udp(53000, 53, dns_query(1, "abc.exfil-c2.net")))
        )
        response = ethernet(
            ipv4(
                "8.8.8.8",
                "172.17.0.2",
                17,
                udp(53, 53000, dns_query(1, "abc.exfil-c2.net", response=True)),
            )
        )
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        try:
            handle.write(build_pcap([query, response]))
            handle.close()
            events = pcap.parse_pcap(handle.name)
        finally:
            os.unlink(handle.name)

        # 响应不能被当成一次新的查询，否则隧道计数会翻倍。
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].dst_port, 53)

    def test_server_to_client_packets_are_ignored(self):
        """veth 双向抓包时，服务器回包不能被算成 Agent 外联。"""
        import tempfile

        from tests.helpers import build_pcap, ethernet, ipv4, tcp

        # 服务器 443 -> 客户端临时端口，载荷是 TLS ServerHello 形态
        server_hello = b"\x16\x03\x03\x00\x20" + b"\x02" + b"\x00\x00\x1c" + b"\x00" * 32
        frame = ethernet(ipv4("45.77.12.9", "172.17.0.2", 6, tcp(443, 50111, server_hello)))
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        try:
            handle.write(build_pcap([frame]))
            handle.close()
            events = pcap.parse_pcap(handle.name)
        finally:
            os.unlink(handle.name)

        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()
