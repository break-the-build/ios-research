"""experiment-loop entrypoint for the ios-research environments.

Load with experiment-loop's ``--load`` flag; the flag adds this file's directory
to ``sys.path``, so importing the sibling ``ios_env`` package registers every
ios-research environment:

    python -m experiment_loop run goals/06-fuzz-effectiveness.json \
        --load tools/experiment_loop/ios_research_env.py --samples 40

Registered environments (bound to real ios-research code):

    ios_research_fuzzer         goals 05 (throughput), 06 (effectiveness)
    ios_research_minimizer      goal  09 (testcase-minimization)
    ios_research_corpus         goal  07 (corpus-quality)
    ios_research_crash_analysis goals 08 (deduplication), 11 (root-cause)
    ios_research_differential   goal  12 (differential-testing)

Each exposes a ``run(config, samples, seed) -> Observation`` and reports the
metrics its goal declares. Safety: mock targets and in-process code paths only;
no capability outside the authorized-research boundary.
"""

from __future__ import annotations

import ios_env  # noqa: F401  (import registers all environments)

__all__ = ["ios_env"]
