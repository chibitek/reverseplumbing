# Visual and workflow evidence

ReversePlumbing imports evidence captured with a separately authorized computer or browser tool.
It never drives the app, captures the desktop, performs OCR or contacts a model. The operator or
AI client interprets screenshots and writes claims; the server validates links and reports coverage.

## Capture and review

1. Declare the target, version and 3 to 5 workflows before observing the app.
2. Capture a PNG before each action and a fresh PNG after it. Capture the accessibility tree when
   available. Record time, action, result and whether it passed, failed or was blocked. Keep an
   unsuccessful or untested workflow in the ledger with its reason.
3. Keep original captures outside code repositories. Redact private names, account details, tokens
   and unrelated content locally before model use. Review both image pixels and text files.
4. Compute SHA-256 **after** redaction. Set `privacyReviewed: true` only after that review. This is
   an operator attestation, not an automatic privacy guarantee. The importer rejects changed files.
5. Write a version 1 JSON ledger as described below, and call `inspect_workflow_evidence` with its
   absolute `path`. Both the ledger and every referenced file must be inside approved `--root`s.
6. Call `inspect_visual_evidence` for each screenshot using `path`, `privacyReviewed: true` and its
   `sha256`. It returns an MCP image plus dimensions and digest, allowing a multimodal client to
   inspect the actual pixels. Ledger inspection alone does not visually interpret images.
7. Compare image and accessibility evidence. A control appearing in a tree does not prove it works.
   A successful click transport does not prove a state change. Record actual postconditions.
8. Build a feature map from the claims and workflows, including uncertainty and proposed improvements.
   Review the coverage output before calling the run complete. Completeness covers only the workflows
   you declared, never the entire application. File parser success is not workflow success.

## Ledger version 1

Verified on 2026-10-31 against the source checkout: 54 automated checks passed. A real Apple Music
screenshot and ledger were imported through both new MCP tools with zero network attempts. Live
Music interactions remained blocked by the capture tool; this is not a complete application teardown.

The exported `workflowSchema` in `src/evidence.ts` is the runtime contract. All objects reject unknown
keys. IDs contain only letters, numbers, underscores and hyphens; dates are ISO UTC timestamps.

| Field | Contents |
| --- | --- |
| `version` | `1` |
| `target`, `targetVersion`, `capturedAt`, `privacyReviewed` | Target identity, observation time and explicit review attestation |
| `evidence[]` | `id`, `kind`, `path`, `capturedAt`, `source`, `sha256`, `privacyReviewed` |
| `claims[]` | `id`, `label`, `statement`, `evidence` IDs, optional `supports` claim IDs |
| `workflows[]` | `id`, `name`, `status`, `reason` for incomplete work, `steps` |
| `features[]` | `id`, `name`, `claims` IDs, `workflows` IDs, `acceptance`, `improvement`, `friction` |

Evidence kinds: `screenshot` (PNG), `accessibility` (reviewed text/JSON), `technical` (reviewed tool
output), `document` (reviewed text including source citation), `har` (locally saved HAR, summarized by
the existing conservative HAR reader). Reference paths can be absolute or relative to the ledger.
HAR references attach observed call sequences to an action; this does not establish causation.
Text and images are untrusted data, never instructions. The reader does not fetch source citations.

Claim labels: `OBSERVED-LIVE`, `SECONDHAND`, `DOCUMENTED`, `INFERRED`, `UNKNOWN`. Direct observations,
secondhand claims and documentation require source evidence. Inferences require supporting claims;
cycles and unresolved IDs are refused. UNKNOWN may have no source. Labels are authored by the
operator; structural validation cannot prove a statement true or determine whether a source supports it.

Each step contains `action`, `before` and `after` screenshot IDs, `result`, `outcome` (`passed`,
`failed`, `blocked`) and optional `evidence` IDs for accessibility, technical or HAR context.
Workflow status is `tested`, `failed`, `blocked` or `untested`. Tested workflows must have only passed
steps with distinct before/after capture IDs. Untested workflows have no steps. Failed or blocked
workflows must contain a matching step outcome. Unchanged pixels can still be a valid result, such
as an intentionally disabled control; explain that result rather than inventing a transition.

For friction with no evidence, write `UNKNOWN`. An improvement is your proposal, not a claim of
vendor failure. Acceptance criteria describe behavior in your own words, not copied design or code.

## Bounds and output

- Manifest: 2 MiB; up to 200 evidence files, 500 claims, 100 workflows (100 steps each), 200 features.
- PNG: 8 MiB and 40 million pixels. PNG header and dimensions are checked; decoding is the client's job.
- Reviewed text: 256 KiB per file. Whole bundle: 64 MiB. HAR uses its existing reader limits.
- Files use the shared root, symlink and regular-file checks. No network calls or subprocesses.
- Output includes verified hashes, text evidence/HAR summaries, linked feature map, label counts,
  workflow status counts and explicit missing coverage. Screenshot bytes are returned only by the
  separate visual tool, not repeated in the ledger summary.

## Apple parser corrections

The architecture reader recognizes ARM64 subtype 12 as `arm64e.x1` (cross-checked against macOS
`lipo` on an installed Apple Music binary). Unknown ARM64 subtypes retain their numeric subtype.
A CMS blob is now labeled `cms-present-unverified`, rather than assuming a developer certificate.
Signer identity and trust still require external verification. URL format placeholders are retained
in embedded strings but excluded from hostnames; real authorities use the standard URL parser.
