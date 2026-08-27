# S20-700 Authorized Adapter Binding Slice

Status: bounded landed-surface slice; **full S20-700 remains incomplete**

This slice hardens the narrow local S20-380 authorized reference-adapter
wrapper. It introduces no VM integration, live host authority, candidate
admission, transaction, provider, or deployment surface.

The table-driven regression fixes three exact request/token confusion cases:

- invocation under a state root different from the authenticated token;
- invocation with an effect ID different from the authenticated token;
- invocation through an adapter ID different from the authenticated token.

Each case must return `AuthorizedAdapterInvocationError::Capability` with its
exact `CAP_*_MISMATCH` code. The replay/budget ledger must remain new, the
fixture must remain byte-for-byte equal to its pre-call clone, and execution
must not produce an after-authorization receipt. This directly asserts that
binding failures precede both capability charge and adapter execution.

Focused validation:

```text
cargo test -p sley-adapter authorized_adapter_request_binding_confusion_fails_before_charge --locked
python3 scripts/check_capability_token.py
make adversarial
```

This is an adversarial regression slice, not a persistent fuzz harness or full
S20-700 finding register. VM-integrated/live adapters and the other master-goal
fuzz surfaces remain deferred.

Vulcan's independent review found no open P0, P1, or P2 issue in this bounded
slice and confirmed the exact error precedence and no-mutation assertions.
