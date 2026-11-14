# Change kinds

Every reported change has one kind. SARIF output uses them as rule ids (`tessera/<kind>`).

## added

An entry exists now that was not in the baseline.

## removed

An entry from the baseline no longer exists, and no added file has the same content.

## modified

Content changed: the content hash, the size or a symlink target differs. Other changed attributes are listed with it.
For `append` profiles, *modified* means the file shrank.

## metadata

Content is unchanged, but tracked metadata differs: permissions, owner, group, platform attributes or timestamps.
Rated one level below the rule's severity. Changes to only `mtime`, inode or link count are capped at `low`.

## type_changed

The entry changed type, for example a regular file replaced by a symbolic link. Rated one level above the rule's
severity because it is a common way to redirect privileged programs.

## moved

A file was removed and a file with identical content and size appeared elsewhere. The report shows the old path.

## unreadable

The entry was readable when the baseline was taken and cannot be read now (permission denied, locked by another
process). Treated as a change because hiding a file by making it unreadable is a known evasion technique.
