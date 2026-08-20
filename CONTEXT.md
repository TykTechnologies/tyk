# WAF experiment glossary

**Track** — One independent WAF implementation evaluated by this experiment.

**Common Baseline** — The exact Gateway commit, CRS release, request corpus,
benchmark environment, and decision weights shared by both Tracks.

**Shared Corpus** — The identical requests and expected outcomes used to test
both Tracks.

**Applicable Test** — A Shared Corpus test whose required inputs and semantics
the Track claims to support.

**Unsupported Feature** — A required behavior that a Track identifies and does
not claim to implement. It is not an unexpected failure.

**Comparison Result** — The retained evidence for both Tracks. It is distinct
from the later productionisation decision.
