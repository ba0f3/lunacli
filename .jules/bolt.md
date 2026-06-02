## 2026-06-01 - Prevent recompiling Regexes in loops
**Learning:** Recompiling dynamic patterns from configuration properties (`pol.DenyPatterns` via `regexp.MatchString`) inside frequently-called functions (`Classify`) introduces a significant bottleneck as command classification is run often.
**Action:** When a configuration object holding patterns is created or loaded (e.g. `NewEngine`), compile the regular expressions once and store the resulting array inside the instance structure. Use `re.MatchString(cmd)` directly.

## 2026-06-02 - Prevent string builder allocations
**Learning:** Re-allocating `strings.Builder` and iterating over character arrays for functions like `unescape` is unnecessarily expensive when the string has no characters that need manipulation. In cases where the string does require manipulation, dynamically resizing the builder introduces minor overhead.
**Action:** Always check if string operations (like unescaping or replacing characters) are actually required using something like `strings.ContainsRune`. If not, return early. Furthermore, when creating `strings.Builder` use `b.Grow(len(s))` to pre-allocate capacity whenever the max length is known.
