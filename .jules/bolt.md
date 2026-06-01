## 2026-06-01 - Prevent recompiling Regexes in loops
**Learning:** Recompiling dynamic patterns from configuration properties (`pol.DenyPatterns` via `regexp.MatchString`) inside frequently-called functions (`Classify`) introduces a significant bottleneck as command classification is run often.
**Action:** When a configuration object holding patterns is created or loaded (e.g. `NewEngine`), compile the regular expressions once and store the resulting array inside the instance structure. Use `re.MatchString(cmd)` directly.
