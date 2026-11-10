"""Run every CageSight mode against the bundled demo data.

    python demo/run_demo.py

Outputs land in demo/out/ and can be attached to a report or a blog post.
"""

from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from cagesight.demo import write_demo  # noqa: E402


def main() -> int:
    out_dir = os.path.join(ROOT, "demo", "out")
    paths = write_demo(out_dir)
    print("demo data -> %s" % out_dir)

    commands = [
        [sys.executable, "-m", "cagesight", "scan", paths["events"], "--format", "md",
         "--out", os.path.join(out_dir, "report-events.md")],
        [sys.executable, "-m", "cagesight", "pcap", paths["pcap"], "--format", "md",
         "--out", os.path.join(out_dir, "report-pcap.md")],
        [sys.executable, "-m", "cagesight", "scan", os.path.join(ROOT, "demo", "samples", "auditd.log"),
         "--format", "table", "--no-color"],
        [sys.executable, "-m", "cagesight", "scan", os.path.join(ROOT, "demo", "samples", "agent.strace"),
         "--format", "table", "--no-color"],
        [sys.executable, "-m", "cagesight", "audit-config", os.path.join(ROOT, "demo", "insecure-compose.yml"),
         "--format", "md", "--out", os.path.join(out_dir, "report-audit.md")],
    ]

    for command in commands:
        print("\n$ " + " ".join(command))
        completed = subprocess.run(command, cwd=ROOT)
        if completed.returncode not in (0, 2):
            return completed.returncode
    print("\n所有报告已写入 %s" % out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
