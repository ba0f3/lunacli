## 2026-06-01 - Prevent recompiling Regexes in loops
**Learning:** Recompiling dynamic patterns from configuration properties (`pol.DenyPatterns` via `regexp.MatchString`) inside frequently-called functions (`Classify`) introduces a significant bottleneck as command classification is run often.
**Action:** When a configuration object holding patterns is created or loaded (e.g. `NewEngine`), compile the regular expressions once and store the resulting array inside the instance structure. Use `re.MatchString(cmd)` directly.

## 2026-06-02 - Prevent string builder allocations
**Learning:** Re-allocating `strings.Builder` and iterating over character arrays for functions like `unescape` is unnecessarily expensive when the string has no characters that need manipulation. In cases where the string does require manipulation, dynamically resizing the builder introduces minor overhead.
**Action:** Always check if string operations (like unescaping or replacing characters) are actually required using something like `strings.ContainsRune`. If not, return early. Furthermore, when creating `strings.Builder` use `b.Grow(len(s))` to pre-allocate capacity whenever the max length is known.

## 2026-06-03 - Prevent strings manipulation inside prefix matching loops
**Learning:** Re-evaluating `strings.ToLower` and `strings.TrimRight` repeatedly inside a hot loop traversing static string maps (like allowlist prefixes evaluation for shell commands) introduces a significant runtime overhead due to unnecessary allocations per item.
**Action:** Precalculate cleaned/normalized structure forms (e.g. `commandPrefix` with exact vs prefix variations) during package initialization (`init`) to iterate fast over pre-computed comparisons using `==` and `strings.HasPrefix`.
## 2026-06-05 - Prevent linear scanning of allowlist prefixes
**Learning:** A linear scan over dozens of static command prefixes inside `Classify` creates unnecessary overhead. Because prefix matches naturally share the same first word as the matched command, we can safely group prefixes by their first word.
**Action:** Store and query prefix allowlists using a `map[string][]commandPrefix` keyed by the first word of the prefix, enabling fast O(1) bucketing before performing localized iterations.

## 2026-06-06 - Prevent strings.ToLower and slice allocations in non-matching cases
**Learning:** Calling `strings.ToLower` on every command argument inside `isSemanticMutation` forces array slice allocations and O(N) lowercasing when evaluating commands that don't need it (which is 99% of all commands).
**Action:** When performing switch/case evaluations over specific command names that require case-insensitive arguments matching, evaluate the base command match *before* dynamically allocating the lowercase slice.
## 2026-06-07 - Prevent strings.ToLower and slice allocations in non-matching cases
**Learning:** Allocating lower-cased versions of strings to evaluate regex match for mutating commands causes memory waste and compute time overhead if the command doesn't actually have a chance to be evaluated.
**Action:** Move allocations such as `strings.ToLower` right before the conditional block that requires it, evaluating previous fast conditions (like `hasMutatingFlagPatterns`) first.
