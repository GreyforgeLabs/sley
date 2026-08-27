# sley-mutate

S20-340 immutable mutation-schema descriptors generated from the frozen SSMC1
epoch-1 manifest.

This crate describes all eighteen entity kinds, their fields, and the sixteen
closed primitive mutation classes. It cannot construct candidates, mutate an
entity or repository, evaluate preconditions, establish root/session/workspace
authority, validate policy or capabilities, or commit transactions. Those are
later work packages.
