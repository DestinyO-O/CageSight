"""Detector registry."""

from __future__ import annotations

from typing import List

from cagesight.detectors.base import BaseDetector
from cagesight.detectors.credential import CredentialDetector
from cagesight.detectors.dns import DnsTunnelDetector
from cagesight.detectors.egress import EgressDetector
from cagesight.detectors.escape import EscapeDetector
from cagesight.detectors.execchain import ExecChainDetector
from cagesight.detectors.staging import StagingDetector

DETECTOR_CLASSES = [
    DnsTunnelDetector,
    EgressDetector,
    CredentialDetector,
    EscapeDetector,
    StagingDetector,
    ExecChainDetector,
]


def build_detectors() -> List[BaseDetector]:
    return [cls() for cls in DETECTOR_CLASSES]


__all__ = ["BaseDetector", "build_detectors", "DETECTOR_CLASSES"]
