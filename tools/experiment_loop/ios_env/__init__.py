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
from . import minimizer       # ios_research_minimizer       (goal 09)
from . import corpus          # ios_research_corpus          (goal 07)
from . import crash_analysis  # ios_research_crash_analysis  (goals 08, 11)
from . import differential    # ios_research_differential    (goal 12)

__all__ = ["fuzzer", "minimizer", "corpus", "crash_analysis", "differential"]
