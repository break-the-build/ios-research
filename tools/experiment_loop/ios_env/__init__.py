"""experiment-loop environments for ios-research.

Importing this package registers every ios-research environment with the
experiment-loop registry. Load it from the CLI with::

    python -m experiment_loop run <goal.json> \
        --load tools/experiment_loop/ios_research_env.py --samples 40

Each environment binds the *real* ios-research code to the experiment-loop
search engine via a ``run(config, samples, seed) -> Observation`` method, so the
loop optimizes actual framework behavior rather than a simulation. Every
environment exposes the metrics declared by its corresponding goal in
``goals/``.

Safety: these environments exercise only the framework's mock targets and
in-process code paths. They introduce no new capability and stay entirely within
the authorized-research boundary.
"""

from __future__ import annotations

# Importing each module runs its @register decorator.
from . import fuzzer          # ios_research_fuzzer          (goals 05, 06)
from . import fuzzer_engine   # ios_research_fuzzer_engine   (goal 05, real engine)
from . import minimizer       # ios_research_minimizer       (goal 09)
from . import corpus          # ios_research_corpus          (goal 07)
from . import crash_analysis  # ios_research_crash_analysis  (goals 08, 11)
from . import differential    # ios_research_differential    (goal 12)
from . import research        # ios_research                 (goal 13)
from . import agent           # ios_research_agent           (goals 14, 15)
from . import reporting       # ios_research_reporting       (goal 17)
from . import device_matching  # ios_research_device_matching (goal 18, issue #11)
from . import bounty_readiness  # ios_research_bounty_readiness (goal 21)
from . import detection_quality  # ios_research_detection     (goal 22)
from . import cve_regression    # ios_research_cve_regression (goal 23)
from . import pipeline_latency  # ios_research_pipeline_latency (goal 24)

__all__ = ["fuzzer", "fuzzer_engine", "minimizer", "corpus", "crash_analysis",
           "differential", "research", "agent", "reporting", "device_matching",
           "bounty_readiness", "detection_quality", "cve_regression",
           "pipeline_latency"]
