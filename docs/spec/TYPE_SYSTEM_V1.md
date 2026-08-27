# Type System v1

Status: M0 normative draft.

The type system is explicit, deterministic, and has no implicit widening,
narrowing, null, hidden exception, or untyped foreign call.

## Core types

`Unit`, `Bool`, signed and unsigned integers at explicit widths, deterministic
`F32`/`F64`, `Bytes`, exact-scalar-sequence `Text`, fixed tuples, records, tagged
variants, vectors, canonical ordered maps, `Option<T>`, `Result<T,E>`, function
references, opaque adapter handles, and capability-token types.

## Definitions

Type definitions bind stable field/case identities, declared semantic order,
parameters where enabled, invariants, and visibility. Labels and physical
layout are not type identity. Recursive types require an epoch-declared,
termination-safe rule and are otherwise rejected in the first implementation.

Type parameters are invariant in v1. Generic instantiation is explicit and
monomorphically checkable; there is no implicit coercion, subtyping, variance,
or higher-kinded inference. Instantiation identity binds the generic definition
and ordered canonical type arguments.

## Equality, ordering, and hashing

`Unit`, booleans, integers, bytes, exact text, tuples, records, variants,
vectors, options, results, and function references have structural equality
when every component type supports equality. Ordered maps use the total order
of their declared key type. Floating equality follows the frozen IEEE profile;
NaNs compare unequal and canonical hashing uses canonicalized bits. Opaque
handles and capability tokens support identity comparison only within their
bound session/root and are neither orderable nor persistable as ordinary
canonical values.

Integer arithmetic is checked: overflow, division by zero, signed-minimum
division by negative one, and invalid shifts produce explicit typed operation
failure. Wrapping, saturating, and trapping variants require distinct opcodes;
there is no build-profile-dependent behavior.

`Result<T,E>` models recoverable program failure. The trap terminator is
reserved for epoch-defined unrecoverable VM failures and carries a typed code;
it cannot be caught or silently converted to `Result`. Function-reference
identity is the stable target `EntityId` plus explicit type arguments and never
an address, object layout, or label.

## Checking

The checker establishes operation operand/result types, block-parameter edges,
call arity and type equality, dominance and use, result completeness, explicit
failure paths, effect declarations, adapter signature identity, and capability
token narrowing. Every failure identifies phase, relevant entity/object IDs,
and a stable code without depending on source locations.

## Floating profile

Floating operations use IEEE-754 round-to-nearest ties-to-even, preserve
subnormals, forbid implicit fused multiply-add and unversioned transcendentals,
and canonicalize NaN results after every operation. Conformance fixtures must
detect host fast-math or architecture divergence.
