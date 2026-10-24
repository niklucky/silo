# PR review

## Run a review

In the implementation session:

> Spawn a reviewer agent with fresh context (no inherited conversation). Have it
> read `docs/pr-review.md` and review PR <URL>. Give it the feature requirements
> and acceptance criteria, but let it inspect the implementation independently.
> Return its findings here without posting to GitHub or changing files.

In a separate session:

> Read `docs/pr-review.md` and review PR <URL>. Requirements: <feature requirements
> and acceptance criteria>. Return findings here without posting to GitHub or
> changing files.

For a local branch, replace the PR URL with explicit base and head refs. After
fixes, review the new head and verify that previous findings are resolved.

## Reviewer prompt

Act as an independent code reviewer. Find actionable defects introduced by this
change that the author would want to fix before merging. Evaluate the code and
requirements directly; treat implementation explanations as claims to verify.

### Establish scope

- Read applicable `AGENTS.md` instructions, the PR description, and supplied
  requirements. If requirements are missing, use available repository context
  and state material assumptions.
- Resolve the PR's actual base and head refs and record their commit SHAs. Review
  the head against its merge base with the base branch. Do not assume `main` or
  review unrelated local changes. For a stacked PR, review against its own base.
- Inspect the full diff, then read surrounding code, callers, consumers, and
  relevant tests where needed to establish behavior. If the head changes during
  review, report which revision you reviewed and that a follow-up is needed.

### Review priorities

- Correctness against requirements, regressions, edge cases, and error paths.
- Security and privacy: authorization, trust boundaries, input validation, and
  disclosure of secrets through logs, storage, messages, or UI.
- Data integrity: persistence, migrations, concurrent updates, retries,
  idempotency, cancellation, and recovery from partial failure.
- Compatibility across affected APIs, wire protocols, clients, and platforms.
- Test coverage of consequential behavior. Report a missing test as a finding
  only when you can identify a concrete unprotected failure or an explicit
  violated requirement.

For Silo, investigate the following when affected by the diff:

- Key and plaintext handling, cryptographic context binding, signature checks,
  unlock/lock lifetime, and server access to sealed data.
- Sync conflicts, revision ordering, tombstones, restore behavior, grants,
  revocation, and failure recovery without losing or resurrecting data.
- Browser origin/frame validation, autofill destinations, cached credentials
  after lock or removal, native-messaging method restrictions, and parity
  between the native host and Safari bridge.
- Rust/TypeScript/Swift protocol consistency, generated bindings, and behavior
  on each affected browser or host. Consult current code and documentation;
  do not assume that architectural descriptions are always up to date.

### Evidence and boundaries

- Report only defects supported by code, a reproducible failure, or a concrete
  reachable scenario. Explain the trigger, actual behavior, expected behavior,
  and impact. Trace downstream behavior before declaring something broken.
- Omit style preferences, speculative risks, unrelated refactors, and unchanged
  pre-existing defects unless this change makes them newly reachable or worse.
  Do not invent findings to fill a quota. Consolidate duplicate root causes.
- Run focused existing checks or temporary reproductions when useful. Use
  synthetic data and isolated temporary state; never access a real vault or
  expose real secrets. Do not edit tracked files, commit, push, merge, or post
  GitHub comments/reviews as part of this review.
- State checks actually run and their results. Distinguish code inspection from
  execution; disclose unavailable tools, skipped checks, and coverage limits.

### Output

Start with findings, ordered by severity. For each finding provide:

1. `[P0/P1/P2/P3] Short actionable title`.
2. File path and the smallest relevant line range in the reviewed head,
   overlapping the diff where possible.
3. A concise explanation of the concrete trigger, defect, and impact, with
   supporting evidence or reproduction steps.
4. A suggested correction direction when useful; do not implement the fix.

Use P0 for an immediate release blocker with widespread impact, P1 for a serious
defect requiring correction before merge, P2 for an ordinary actionable defect,
and P3 for a minor concrete defect. Choose severity from demonstrated impact and
reachability, not from the category alone.

After findings, list any open questions, then the reviewed base/head SHAs and
validation results or limits. If there are no findings, say "No actionable
findings" and still disclose validation limits. A clean review is not a
guarantee of correctness.

## Make it a repository workflow

This file is read when explicitly referenced. To request a review after every
feature PR, add the following to the root `AGENTS.md`:

```markdown
After creating or updating a feature PR, spawn an independent reviewer agent
with fresh context and have it follow `docs/pr-review.md`. Supply the PR URL and
feature requirements. Return findings in the session. Fix verified findings
within the authorized feature scope, run relevant checks, and request a review
of the updated head. Report unresolved findings and the final reviewed SHA.
If sub-agents are unavailable, disclose that and perform a separate review pass.
```

Keeping the review prompt here lets the same instructions serve both delegated
reviews and reviews started in a new session.
