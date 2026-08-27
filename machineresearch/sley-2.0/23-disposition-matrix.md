# Legacy Disposition Matrix

| Legacy surface | Decision | Sley 2 equivalent | Acceptance evidence |
|---|---|---|---|
| accepted/rejected corpus | preserve evidence | independent semantic corpus | disposition per migrated concept; no source dependency |
| stable graph identity | reimplement | EntityId/ObjectId/StateRoot | domain/hash/id properties |
| typed graph checking | reimplement | SSMC/check kernel | positive/negative conformance |
| effects/authority fixtures | preserve and reimplement concept | effects + policy/capability | no ambient authority tests |
| stale plans/rollback/transaction tests | preserve evidence | candidate/txn/crash suites | invalid state unchanged |
| benchmark methodology/results/failures | preserve | fixed succession harness | all trials retained |
| parser/AST/source/formatter | reject | none | GA dependency denylist |
| LSP/Tree-sitter/editor/workbench | reject | SMP1/query/mutation | release inventory denylist |
| source diffs/review packets | reject | semantic comparison/conflict | no text merge/review dependency |
| self-hosting/bootstrap experiments | preserve negative evidence; defer | none for GA | absence from critical path |
| ZJX/Siglum integrations | defer/optional transport evidence | external adapters only | kernel builds without them |

Every future legacy-derived implementation idea requires a dedicated ADR before
code enters the kernel.
