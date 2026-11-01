from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gitdiagram_core.analyzer import AnalysisConfig, AnalysisResult, run_analysis

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sample_app"


@lru_cache(maxsize=1)
def fixture_result() -> AnalysisResult:
    return run_analysis(AnalysisConfig(root=FIXTURE))
