package vulnintel

import (
	"fmt"
	"strconv"
	"strings"
)

// semver range matching: compare a GHSA `vulnerable_version_range` expression against the
// target version.
//
// ## Why hand-written instead of a library
//
// 1) The host environment is not guaranteed to have a semver toolchain (this is the minimal
//    image the agent runs in);
// 2) The expression shape is actually narrow: GHSA only uses comma-separated AND conditions,
//    each `<op> <version>` (op in {<, <=, >, >=, =}), with **no** `||` disjunction and **no**
//    `^`/`~` range shorthand (measured: GitHub's data always uses explicit bounds).
// 3) The cost of a wrong verdict is asymmetric: **judging "not affected" by mistake makes the
//    model skip the vulnerability outright** — exactly where freshly disclosed CVEs are lost
//    most easily. So when unsure, always judge "possibly affected".
//
// ## Conservative policy
//
// - The target version cannot be parsed (pre-release with a suffix, custom version string) →
//   judging **not affected** would be wrong; "possibly affected" is right. So a parse failure →
//   Affected=true, with Reason stating "cannot parse".
// - The range expression has an unrecognized operator → likewise Affected=true (conservative).
// - The range is empty (GHSA supplied a package but no range) → Affected=true plus an explicit
//   note that "GHSA gave no range".

// semverRange is one parsed version constraint.
type semverRange struct {
	// Op is the comparison operator: < <= > >= =.
	Op string
	// Ver is the version being compared against.
	Ver semver
	// Raw is the original text (for error messages).
	Raw string
}

// semver is a comparable version number.
type semver struct {
	Major, Minor, Patch int
	// Pre is the pre-release identifier (1.0.0-alpha → "alpha"). Empty = release version.
	Pre string
	// Valid false means parsing failed.
	Valid bool
	// Comparable false means "it parsed, but it should not be compared against release
	// versions".
	//
	// Examples: 8.3.1-dev-build, 1.0.0-SNAPSHOT, 2.0.0-patch1 — these are **development/build
	// versions** whose version number is not stable (the next build may still be
	// 8.3.1-dev-build with different content). Comparing them against GHSA's "< 3.10.0" yields
	// a **false conclusion**.
	//
	// The error directions are asymmetric: judging "not affected" by mistake makes the model
	// skip the vulnerability, so this case is always treated as "possibly affected".
	Comparable bool
}

// parseSemver parses a version number.
//
// Supports: `1`, `1.2`, `1.2.3`, `1.2.3-alpha.1`, `v1.2.3`, `1.2.3-rc1`. Only the first three
// numeric segments are taken and the rest ignored (PHP's 8.3.1 and .NET's 4.8.1 are enough).
func parseSemver(s string) semver {
	v := semver{}
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" {
		return v
	}
	// Pre-release: split off the part after -.
	pre := ""
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	nums := make([]int, 0, 3)
	for _, p := range parts {
		if len(nums) >= 3 {
			break
		}
		// A segment may carry a non-numeric suffix (8.3.1RC1) — take the numeric prefix.
		digits := leadingDigits(p)
		if digits == "" {
			break
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			break
		}
		nums = append(nums, n)
	}
	if len(nums) == 0 {
		return v
	}
	v.Major = nums[0]
	if len(nums) > 1 {
		v.Minor = nums[1]
	}
	if len(nums) > 2 {
		v.Patch = nums[2]
	}
	v.Pre = pre
	v.Valid = true
	// Pre-release/development suffix → parsed but not comparable (see the semver.Comparable
	// comment).
	v.Comparable = isComparablePre(pre)
	return v
}

// isComparablePre reports whether a pre-release identifier can be ordered against a release
// version.
//
// Pre-releases in the spec (alpha/beta/rc) **have a defined order** (1.0.0-alpha < 1.0.0) and
// can be compared. Development/build identifiers (dev, snapshot, build, rc1, patch1...) carry
// no such guarantee — the version number is unstable and any comparison is meaningless.
func isComparablePre(pre string) bool {
	if pre == "" {
		return true
	}
	p := strings.ToLower(pre)
	for _, marker := range []string{"dev", "snapshot", "build", "nightly", "git", "dirty", "local", "patch"} {
		if strings.Contains(p, marker) {
			return false
		}
	}
	// Spec pre-releases: alpha / beta / rc (may carry a numeric suffix).
	normalized := strings.TrimRight(p, "0123456789")
	switch normalized {
	case "alpha", "beta", "rc", "pre", "preview":
		return true
	}
	// Unrecognized shapes → not comparable (conservative).
	return false
}

// leadingDigits takes the leading run of digits of a string.
func leadingDigits(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return s[:i]
		}
	}
	return s
}

// compareSemver compares two versions: -1 / 0 / 1.
//
// A pre-release is **less than** the release version with the same numbers (semver spec:
// 1.0.0-alpha < 1.0.0).
func compareSemver(a, b semver) int {
	if a.Major != b.Major {
		if a.Major < b.Major {
			return -1
		}
		return 1
	}
	if a.Minor != b.Minor {
		if a.Minor < b.Minor {
			return -1
		}
		return 1
	}
	if a.Patch != b.Patch {
		if a.Patch < b.Patch {
			return -1
		}
		return 1
	}
	switch {
	case a.Pre == "" && b.Pre == "":
		return 0
	case a.Pre == "":
		return 1 // release > pre-release
	case b.Pre == "":
		return -1
	case a.Pre < b.Pre:
		return -1
	case a.Pre > b.Pre:
		return 1
	}
	return 0
}

// String renders the version back into a string (for writing into the CPE range column).
//
// It renders the zero-padded three-segment form (1 → 1.0.0) because VersionInRange's
// cmpVersions compares segment by segment: differing segment counts do not change the result,
// but writing all three is easier to display.
func (v semver) String() string {
	if !v.Valid {
		return ""
	}
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// ParseGhsaRange parses a GHSA version range expression.
//
// Supported shape: comma-separated AND conditions, each `<op> <version>`. Entries that cannot
// be parsed are skipped and recorded in unknown — the caller uses that to take the
// conservative path.
func ParseGhsaRange(expr string) (conds []semverRange, unknown []string) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}
	for _, part := range strings.Split(expr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 1 {
			// Bare version: treat it as "= that version".
			if v := parseSemver(fields[0]); v.Valid {
				conds = append(conds, semverRange{Op: "=", Ver: v, Raw: part})
				continue
			}
			unknown = append(unknown, part)
			continue
		}
		op := fields[0]
		switch op {
		case "<", "<=", ">", ">=", "=":
		default:
			unknown = append(unknown, part)
			continue
		}
		verStr := fields[1]
		// Handles `<= 2.0` with a space as well as `<=2.0` (already split by Fields).
		v := parseSemver(verStr)
		if !v.Valid {
			unknown = append(unknown, part)
			continue
		}
		if !v.Comparable {
			// The range endpoint itself is a development build → this condition cannot be judged;
			// let the caller take the conservative path.
			unknown = append(unknown, part)
			continue
		}
		conds = append(conds, semverRange{Op: op, Ver: v, Raw: part})
	}
	return conds, unknown
}

// GhsaVersionAffected reports whether the target version falls inside the affected range given
// by GHSA.
//
// Return values:
//   - Affected=false: **definitely** outside the range (both the range and the target version
//     parsed).
//   - Affected=true: possibly affected — either genuinely inside the range or **undecidable**
//     (the version does not parse, the range has an unknown operator, the range is empty). The
//     conservative direction is "rather a false positive".
//   - Reason: the basis of the verdict, for humans/the model.
func GhsaVersionAffected(pkg GhsaPackage, targetVersion string) GhsaAffected {
	res := GhsaAffected{Package: pkg}
	target := parseSemver(targetVersion)
	if strings.TrimSpace(pkg.Range) == "" {
		res.Affected = true
		res.Reason = fmt.Sprintf("GHSA gave no affected version range (package %s) — treated as possibly affected", pkg.Name)
		return res
	}
	conds, unknown := ParseGhsaRange(pkg.Range)
	if len(conds) == 0 {
		res.Affected = true
		res.Reason = fmt.Sprintf("GHSA version range %q cannot be parsed (%s) — treated as possibly affected", pkg.Range, strings.Join(unknown, "; "))
		return res
	}
	if !target.Valid {
		res.Affected = true
		res.Reason = fmt.Sprintf("target version %q cannot be parsed and the GHSA range is %q — treated as possibly affected (verify manually)", targetVersion, pkg.Range)
		return res
	}
	if !target.Comparable {
		res.Affected = true
		res.Reason = fmt.Sprintf("target version %q is a development/pre-release build (its version number is unstable and cannot be ordered against a release range); "+
			"the GHSA range is %q — treated as possibly affected (verify manually)", targetVersion, pkg.Range)
		return res
	}
	// Every condition in the range must hold (AND).
	for _, c := range conds {
		cmp := compareSemver(target, c.Ver)
		ok := false
		switch c.Op {
		case "<":
			ok = cmp < 0
		case "<=":
			ok = cmp <= 0
		case ">":
			ok = cmp > 0
		case ">=":
			ok = cmp >= 0
		case "=":
			ok = cmp == 0
		}
		if !ok {
			res.Affected = false
			res.Reason = fmt.Sprintf("version %s does not satisfy %s (GHSA range %q)", targetVersion, c.Raw, pkg.Range)
			return res
		}
	}
	res.Affected = true
	res.Reason = fmt.Sprintf("version %s falls inside the GHSA affected range %q", targetVersion, pkg.Range)
	if len(unknown) > 0 {
		res.Reason += fmt.Sprintf(" (%s in the range was not recognized and is treated as satisfied)", strings.Join(unknown, "; "))
	}
	return res
}

// GhsaRangeUndetermined reports whether a GHSA entry's version information is "unconfirmed".
//
// Two kinds of "unconfirmed":
//  1. no package information at all (the GHSA entry gave no affected) — it is not a
//     package-level vulnerability (a repository-level advisory, for instance);
//  2. a package exists but the range is empty — GHSA itself has not settled the range yet.
//
// This is the same question as NVD's VersionRangeUndetermined, from two sources — **if either
// source can determine it, it counts as determined**.
func GhsaRangeUndetermined(f GhsaFinding) bool {
	if len(f.Packages) == 0 {
		return true
	}
	for _, p := range f.Packages {
		if strings.TrimSpace(p.Range) == "" {
			return true
		}
	}
	return false
}
