# sley-vm

Derived register bytecode and, in later packages, the deterministic Sley 2
reference VM. S20-260 implements the restricted `O0-restricted-v1` lowering
profile for all five terminators and the validated Boolean opcode subset.
Bytecode and cache entries are disposable evidence, never canonical SSMC state
or validation authority. Unsupported opcode signatures, generics, adapters,
and execution fail closed; no execution is implemented by S20-260.
