# Docroot fixtures

Anything in this directory is copied into every service's `$DOCROOT` at deploy
time (SETUP §4/§5).

These are **props, never flags**. Flags only ever arrive over the wire, per
tick, through the note API — so the build sandbox and the guest image never
contain one, and a player reading their own disk learns nothing.

Use fixtures for the static surface an exploit might pivot through: a stray
`/etc/passwd`-shaped file, a config with an interesting path, a directory
worth traversing into.
