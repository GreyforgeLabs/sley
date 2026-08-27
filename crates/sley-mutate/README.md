# sley-mutate

S20-340 immutable mutation-schema descriptors and the first decomposed S20-350
proposal-value host-model slice, generated from the frozen SSMC1 epoch-1
manifest.

This crate describes all eighteen entity kinds, their fields, and the sixteen
closed primitive mutation classes. Its closed host values cover all eighteen
entity bodies and seventy-five fields without runtime type-name selection, and
all 179 immutable descriptors bind to exact closed value discriminants. The
admission surface performs type selection only; there is no binary value codec.
A crate-private staged codec foundation handles primitive leaves, IDs/roots,
direct enums, ordered lists/options, and canonical entity-ID sets under exact
SCB depth and allocation limits. It also closes all twenty `TypeExpr` variants
and their recursive manifest dependencies, including canonical function-effect
sets. A private non-Option CFG slice closes `MemberId`, value/function
references, immediates, edges, switch cases, trap codes, and the return, branch,
conditional-branch, and variant-switch terminator records while preserving
semantic list order for later validation. Dependency-closed private helpers also
cover `TypeParameterDef`, `RecordField`, `BuiltinFailureValue`, `ContractSource`,
`ContractBinding`, and `ResourceLimits`. `TrapTerminator` and the enclosing
`Terminator` union remain open because the frozen SCB1 and SSMC manifest
`Option<T>` tags conflict. It is not publicly descriptor-selectable, and the
other recursive value families remain open. The crate cannot construct
candidates, mutate an entity or repository, evaluate preconditions, establish
root/session/workspace authority, validate policy or capabilities, or commit
transactions. Those are later work packages.
