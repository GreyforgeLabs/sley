# Candidate Validation Profile v1

Status: S20-345 identity contract; S20-360 result/pipeline contract frozen;
validator implementation pending.

The validation profile is immutable policy-independent data naming the phases
and hard work ceilings a candidate requests. It cannot skip a mandatory phase
or turn unsupported analysis into success.

```text
profile_preimage = "SLEYVAP1" || uvar(1) || len(profile_record) || profile_record
ValidationProfileId = BLAKE3-256("sley2.validation-profile.v1" || profile_preimage)
```

The sole full-v1 profile record contains:

| Tag | Field | Exact value |
|---:|---|---|
| 1 | format_version | `1` |
| 2 | phase_tags | ordered list `1..14` |
| 3 | max_operations | `65,535` |
| 4 | max_preconditions | `65,535` |
| 5 | max_candidate_bytes | `67,108,864` |
| 6 | max_decoded_value_bytes | `67,108,864` |
| 7 | max_graph_work | `10,000,000` |
| 8 | max_selected_tests | `65,535` |

Phase tags are: canonical frame; schema/limits; stale base/preimages; identity;
graph/references; type; CFG; effects; protected capability/policy; contracts;
test planning; supported resource analysis; candidate-root construction; final
candidate/result digest generation.

Host, policy, epoch, or request ceilings may be stricter. No ceiling may be
loosened beyond the selected schema or policy. Missing, reordered, duplicated,
unknown, unsupported, or partially executed phases fail closed. A profile ID
is not evidence that its phases ran; the candidate result must carry exact
phase evidence under S20-360.

`CANDIDATE_RESULT_V1.md` is the owning S20-360 contract. It reconciles the
older master-goal and M0-draft prose to these exact fourteen phases, retains
separate graph/reference and type/CFG terminal decisions, and forbids
caller-asserted phase success.
