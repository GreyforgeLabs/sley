# sley-vm

Derived register bytecode and, in later packages, the deterministic Sley 2
reference VM. S20-260 implements the restricted `O0-restricted-v1` lowering
profile for all five terminators and the validated Boolean opcode subset.
Bytecode and cache entries are disposable evidence, never canonical SSMC state
or validation authority. S20-270 adds `VM_EXEC_RESTRICTED_V1`: integrated
re-lowering, validated/hashable constant inputs, deterministic Boolean
execution, all terminators, strict fuel/value/output/cancellation limits, and a
canonical observation ID. Unsupported opcode signatures, generics, adapters,
live cancellation, and persistent execution/test reports remain fail-closed.
