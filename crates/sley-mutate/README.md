# sley-mutate

S20-340 immutable mutation-schema descriptors and the first decomposed S20-350
proposal-value host-model slice, generated from the frozen SSMC1 epoch-1
manifest.

This crate describes all eighteen entity kinds, their fields, and the sixteen
closed primitive mutation classes. Its closed host values cover all eighteen
entity bodies and seventy-five fields without runtime type-name selection, and
all 179 immutable descriptors bind to exact closed value discriminants. The
admission surface performs type selection only; there is no binary value codec.
It cannot construct candidates, mutate an entity or repository, evaluate
preconditions, establish root/session/workspace authority, validate policy or
capabilities, or commit transactions. Those are later work packages.
