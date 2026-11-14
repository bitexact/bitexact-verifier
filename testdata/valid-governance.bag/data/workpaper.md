# Workflow evidence workpaper - `claims`

_Prepared-by-client evidence. BitExact records this workflow's runs and governance acts; it draws no audit conclusion and enforces nothing. Verification is re-performed by the relying party with no trust in BitExact._

## A. Cover

- **Workflow:** `claims`
- **Owner:** Model Risk   **Criticality:** tier-2
- **Versions seen:** v1
- **Environments:** prod
- **Recorded runs:** 1 (1 sealed)

## B. Scope & boundary

This pack evidences the recorded runs of one named agent workflow and its governance history. A passing verification proves each captured run is intact, sealed, and reconstructable, and the governance ledger is un-edited - **not** that these are the complete set of runs the workflow produced, and **not** a statement of compliance.

## C. Version inventory

| Version | Environments | Recorded runs | Sealed |
|---|---|---|---|
| `v1` | prod | 1 | 1 |

### Executions refused at open

None recorded for this scope.

## D. Governance history

Append-only, hash-chained ledger - verified (3 events).

| When | Act | By |
|---|---|---|
| 2026-11-06T19:22:36.011833+00:00 | created | risk-officer |
| 2026-11-06T19:22:36.023964+00:00 | retention_set | risk-officer |
| 2026-11-06T19:22:36.032593+00:00 | policy_set | risk-officer |

## E. Assertions

| Property provided | Requirement it maps to | Honest limit |
|---|---|---|
| A named workflow with owner, versions, and per-environment runs, enumerable as one inventory. | SR 11-7 (superseded 17 April 2026 by SR 26-2) model inventory and ownership. | Evidence of the runs and acts recorded - not that the inventory is the institution's complete model estate. |
| Registered versions and a hash-chained record of what changed and who promoted it. | SR 11-7 (superseded 17 April 2026 by SR 26-2) change control; DORA change management; EU AI Act Art. 12 lifetime record; FINRA 3110(b)(1) WSP change evidence. | Records the declared change and the promotion act; not a validation of the change, and BitExact gated no deployment. |
| Promotion acts recorded on the ledger, each with the principal who recorded it. | FINRA 3110(a) supervisory system evidence. | Records the act; not the approver's registration or the adequacy of the procedure. |
| Composition drift is detectable and provable (digest + regress). | Material-change detection. | The digest fingerprints declared identifiers, not the underlying bytes. |

## F. Independent verification

```
# from the pack's root - the bag's checksums, every run, and the governance ledger, trusting nothing of ours:
python data/verification/bitexact_verifier.py .
# then pin the recorder key you confirmed out of band:
python data/verification/bitexact_verifier.py . --expect-recorder-key <64-hex public key>
```
Exit 0: everything verified. Exit 3: everything verified, and a run declares capture gaps (counted on the OK line). Exit 2: the FAIL line names what failed. Exit 1: an `error:` line names an input the verifier could not use - no verdict. The governance ledger re-walks as a hash chain - an edited or removed event fails - and must end exactly at the head the recorder key signed in `data/ledger-heads.json`, so dropping its newest events fails too. That holds against whoever handed you the pack only with the recorder key pinned: the OK line says which.

`view.html` shows the runs as readable steps in any browser, offline. It is a reading aid, not a verification result: the verifier renders it again from the bundles and fails the pack if it differs.


## G. Limitations

- **Completeness:** not claimed - these are the runs *recorded* under this workflow, never proof they are all of them.
- **Governance acts are asserted** by the deployer and recorded; the ledger proves they were not edited, not that they were correct or authorized.
- **Version-in-force is derived** from the sealed runs and the recorded promotions; it is not a mutable pointer BitExact keeps.

### Capture controls

#### Run `golden-governed`

- **Capture policy:** the run opened under `b2:ce93a52dbf018155afb7a641931ab9a2ccdee0618363591499c85e095411382e`; its document is `capture-policy-b2-ce93a52dbf018155afb7a641931ab9a2ccdee0618363591499c85e095411382e.json` in this pack, below.
- **Capture outcomes:** 0 fields a capture control touched.


Capture policy document `capture-policy-b2-ce93a52dbf018155afb7a641931ab9a2ccdee0618363591499c85e095411382e.json`, as this pack carries it:

```json
{
 "detectors": {
  "pan": {
   "keep_last4": true
  },
  "iban": {},
  "credentials": {}
 },
 "fields": [
  {
   "kind": "*",
   "path": "*",
   "mode": "scrub"
  }
 ],
 "budget_ms": 1000
}
```

## H. Conclusion & sign-off

BitExact supplies the verifiable facts above and this space; the conclusion is the examiner's to write.

| Role | Name | Date | Conclusion |
|---|---|---|---|
| Preparer | | | (facts as recorded) |
| Auditor | | | |
