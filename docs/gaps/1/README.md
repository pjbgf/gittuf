# Verifiable Repository Snapshots for Hash Algorithm Transitions

## Metadata

* **Number:** 1
* **Title:** Verifiable Repository Snapshots for Hash Algorithm Transitions
* **Implemented:** No
* **Withdrawn/Rejected:** No
* **Sponsors:** Aditya Sirish A Yelgundhalli (adityasaky)
* **Last Modified:** July 28, 2026

## Abstract

Git stores all its objects in a content addressed store located under
`.git/objects`, keyed using SHA-1. Due to known weaknesses with SHA-1, Git has
introduced experimental support for SHA-256 along with a transition
("compatibility") mode that lets a repository carry a bidirectional mapping
between the two hash algorithms. Migrating an existing repository from SHA-1 to
SHA-256 rewrites every object identifier and every reference in a single
operation. This GAP describes how gittuf captures a signed, independently
verifiable snapshot of repository state immediately before and immediately after
such a migration. The pre-migration snapshot is retained after the migration
completes, so that any party can later confirm that no object or reference was
altered, added, or removed during the transition. The design is deliberately
independent of the tooling used to carry out the migration and the tooling used
to verify it: any tool that implements Git's hash function transition can perform
the migration, and the resulting snapshots can be verified with Git, with an
independent reimplementation of the transition, or against a retained SHA-1
repository. gittuf relies on this transition for the underlying hash translation
rather than maintaining a parallel mapping of its own. The broader aim is
cryptoagility: making a hash algorithm transition safe and independently
auditable, so that a repository can move off SHA-256 to a stronger algorithm in
the future by the same mechanism.

## Specification

### Background: Git objects and the Merkle DAG

Git stores all its objects in a content addressed store located under
`.git/objects`. This directory contains subdirectories that act as an index to
the hashes themselves. For example, the Git object for commit
`4dcd174e182cedf597b8a84f24ea5a53dae7e1e7` is stored as
`.git/objects/4d/cd174e182cedf597b8a84f24ea5a53dae7e1e7`. The hash is calculated
across the corresponding object prior to compressing it, and it can be
recalculated as follows:

```
cat .git/objects/4d/cd174e182cedf597b8a84f24ea5a53dae7e1e7 | zlib-flate -uncompress | sha1sum
4dcd174e182cedf597b8a84f24ea5a53dae7e1e7  -
```

There are several types of Git objects: commits, blobs, trees, and tags. Commits
record changes made in the repository. Blobs are files in the repository while
trees map to the directory structure of the repository. Trees contain a record
of blobs and subtrees.

Git commits store a record of their one or more parent commits (creating a
Merkle DAG). Each commit also points to the specific tree object that represents
the root of the repository.

```
git cat-file -p db1c7b0210513a452b0b971e1912d5eb2e3ffcd0
tree 7b968da28453b323a0d3333e3be4030b870d26e4
parent 4dcd174e182cedf597b8a84f24ea5a53dae7e1e7
...
```

Finally, tag objects serve as static pointers to other Git objects (frequently
commits). As with Git commits and trees, the tag object also identifies the
target Git object using its identifier.

The Merkle property is central to this GAP. Because every object names its
children by their content hash, the identifier of a single commit transitively
commits to its entire reachable history: all ancestor commits, and every tree
and blob reachable from them. Pinning the tip of a reference therefore pins the
full set of objects reachable from that reference. A snapshot does not need to
enumerate every object. Recording the tip of each reference in scope is
sufficient to fix the reachable object closure.

### Git's hash function transition and compatibility mode

Git includes experimental support for SHA-256. A repository is initialized with
its object format set to SHA-256, after which all object identifiers are
calculated using SHA-256 and stored in `.git/objects`. The same data structures
are maintained, except all SHA-1 identifiers are replaced with SHA-256
identifiers.

To interoperate with SHA-1 clients and forges, Git also provides a
compatibility mode (`extensions.compatObjectFormat`). In this mode Git maintains
a bidirectional translation between the SHA-1 and SHA-256 names of every object,
so that an object can be addressed by either identifier. A translated name can
be obtained with, for example:

```
git rev-parse --output-object-format=sha256 4dcd174e182cedf597b8a84f24ea5a53dae7e1e7
```

Git already computes and stores this translation as part of the transition, so
there is no reason for gittuf to maintain its own SHA-1 to SHA-256 mapping. The
transition is defined by a public specification rather than by a single binary.
Git provides one implementation, and other tools can perform the migration or
compute the same translation by following the same specification. This GAP is
therefore written against the transition itself, not against any one tool.
During a migration, every object and reference in the
repository is transitioned to the new algorithm at once, including gittuf's own
references and objects (the RSL, policy metadata, and attestations). gittuf
already supports operating on SHA-256 repositories, detecting the object format
per repository and using the matching signature headers, so it can produce and
verify its own metadata on either side of a migration (see
[gittuf/gittuf#1472](https://github.com/gittuf/gittuf/pull/1472)). gittuf's task
is not to maintain a lingering dual-hash state, but to make the migration event
itself independently verifiable.

### The repository snapshot

A repository snapshot is a signed manifest that captures repository state at a
single point in time. It has the following structure.

```
Repository Snapshot

hashAlgorithm: <sha1 | sha256>
refs:
  <ref name>: <tip object ID>
  <ref name>: <tip object ID>
  ...
rslTip: <RSL entry ID>
number: <snapshot number>
migration:                        # post-migration snapshot only, the migrator's claim
  performedBy: <identity of the actor that ran the migration>
  tool: <tool name>
  version: <tool version>
  binaryHash: <hash of the migration tool binary>
  invocation: <command and options used, normalized>
```

The snapshot records the object format in effect, the set of references in scope
along with their tip identifiers (expressed in that object format), and the tip
of the RSL. Including the RSL tip binds the snapshot to gittuf's own record of
repository activity, so that any RSL entries added between two snapshots are
visible during verification.

The post-migration snapshot additionally records the provenance of the migration
event itself: who performed it, the name and version of the tool used, a
cryptographic hash of that tool's binary, and the invocation (command and
options). This block is the migrator's own claim. It is attributed to the actor
that ran the migration and does not appear on the pre-migration snapshot, which
predates the migration. Recording tool, version, and binary hash makes the
migration repeatable. A verifier can obtain the same tool at the same version,
confirm the binary hash, and, because the conversion is deterministic, re-run it
to reproduce the SHA-256 tips recorded in the snapshot without trusting the party
that first performed it.

Reproduction is recorded separately, per attester, rather than in the shared
snapshot body. When a party independently re-derives `S2` and signs it, that
party may attach its own reproduction record, the tool, version, and binary hash
it used, to its signature. This keeps the two facts distinct: signing `S2`
attests the recorded state, while the reproduction record is that signer's
separate claim about how it confirmed the result. A witness who observed the
state without reproducing it therefore does not implicitly vouch for the
migrator's tool. Because reproduction records are per-signer, several parties can
corroborate the same `S2` using distinct tools, and agreement across those
independent reproductions is stronger evidence than any single run. A
reproduction record has the following shape.

```
Reproduction record (attached to a signer's attestation of S2)

reproducedBy: <identity of the verifier>
tool: <tool name>
version: <tool version>
binaryHash: <hash of the tool used to reproduce>
```

A snapshot is a plain, self-describing document. It is signed using standard Git
signing mechanisms (SSH or GPG), so that it can be verified with ordinary
tooling (for example `ssh-keygen -Y verify` or `gpg --verify`) even by a party
that does not run gittuf. Multiple actors may independently attach signatures to
the same snapshot, each optionally carrying a reproduction record, allowing
several parties to attest that they observed the same state before and after the
migration. gittuf stores snapshots as attestations under
`refs/gittuf/attestations` and anchors them in the RSL, but neither storage
location nor gittuf itself is required to verify a snapshot's signatures.

### Scope

A snapshot covers the references it lists and, by the Merkle property, every
object reachable from those references. The set in scope should be stated
explicitly and, by default, is the set of references tracked by gittuf policy
plus gittuf's own references. Objects that are not reachable from any listed
reference (for example dangling objects) are out of scope, as are constructs
that are not captured by reference tips, such as the reflog. Notes and replace
references, if present, must be listed explicitly if they are to be covered.

### Migration workflow

1. **Pre-migration snapshot.** Before the migration, gittuf generates a snapshot
   `S1` with `hashAlgorithm: sha1` recording the in-scope references, their
   SHA-1 tips, and the SHA-1 RSL tip. One or more actors sign `S1`. It is
   anchored in the RSL and retained.
1. **Migration.** The repository is migrated from SHA-1 to SHA-256. Any tool that
   implements Git's hash function transition may perform this step, whether Git's
   own experimental transition support or another converter that follows the same
   specification. Compatibility mode is enabled so that the bidirectional object
   translation is retained. The snapshot design does not depend on which tool is
   used: it records repository state, not the mechanism that produced it. Every
   object and reference, including gittuf's own, is rewritten to SHA-256.
1. **Post-migration snapshot.** After the migration, gittuf generates a snapshot
   `S2` with `hashAlgorithm: sha256` recording the in-scope references, their
   SHA-256 tips, and the SHA-256 RSL tip. `S2` also records the migration event's
   provenance as the migrator's claim: who performed it, the tool, its version, a
   hash of its binary, and the invocation used. `S2` names `S1` (by a digest over
   `S1`'s canonical serialization) so that the two are bound together. One or more
   actors sign `S2`, each optionally attaching a reproduction record for the tool
   it used to re-derive the result. It is anchored in the RSL.

The pre-migration snapshot `S1` is kept after the migration completes. It is the
ground truth against which the migration is judged. Because it is expressed
in the pre-migration algorithm and signed independently of the migration tool,
retaining it lets any party re-run the comparison at any point in the future,
long after the migration has finished.

### Verification workflow

Given the retained `S1` and `S2`, a verifier confirms the migration was faithful
as follows.

1. **Verify signatures.** Check that `S1` and `S2` carry valid signatures from
   the expected actors (per gittuf policy, or per the verifier's own trust
   assumptions when verifying outside gittuf). Where signers attached reproduction
   records, confirm each record is covered by that signer's signature. The
   migration block in `S2` is the migrator's claim and is not, on its own,
   evidence that the migration was faithful. That comes from the correspondence
   checks below and, for the strongest assurance, from independently reproducing
   `S2`.
1. **Verify reference correspondence.** For each reference in `S1`, translate its
   SHA-1 tip to its SHA-256 name and confirm the result equals the tip recorded
   for the same reference in `S2`. Confirm the reverse for each reference in
   `S2`. The set of references must be identical in both snapshots: no reference
   was added or removed.
1. **Verify the RSL.** Confirm the RSL tip recorded in `S2` is the faithful
   translation of the RSL tip in `S1`, so that no unexpected RSL entry was
   introduced during the migration window.

Because tip correspondence combined with the Merkle property transitively covers
the entire reachable object closure, a faithful result across all reference tips
demonstrates that no reachable object was substituted, added, or removed.

#### Obtaining the hash translation

The translation in step 2 maps each SHA-1 name to the SHA-256 name recorded in
`S2`. A verifier can obtain it from more than one source, and the authoritative
source depends on the migration tool (see "Migration tools and what must be
confirmed for each" below). Possible sources include:

* Git's compatibility mode, which already computes the bidirectional mapping when
  the migration produced Git's canonical hash-function-transition names. In the
  common case, a verifier obtains each SHA-256 name directly from Git (for
  example via `git rev-parse --output-object-format=sha256`) rather than
  re-implementing Git's object serialization and re-hashing the graph. This makes
  verification fast and avoids a class of bugs arising from reproducing Git's
  canonicalization rules independently.
* An independent recomputation that re-derives the SHA-256 names from the
  retained pre-migration objects. For a canonical transition this is Git's own
  mapping recomputed from object content. For a tool that transforms content
  during migration, it is a deterministic re-run of that tool, or an equivalent
  reimplementation. This need not be the tool that performed the migration, and
  for adversarial assurance it should not be.
* A mapping emitted by the migration tool as an out-of-band artifact, kept in a
  separate file outside the repository. Such a mapping must not be written back
  into the migrated repository as a new reference or note (for example git-sync's
  default `refs/notes/sha1-origin`), because that adds state absent from `S1` and
  breaks the requirement that the reference set be identical across the two
  snapshots. Any tool-emitted mapping is only as trustworthy as the tool that
  produced it, so for adversarial assurance it must be reproduced by an
  independent, deterministic re-run rather than taken on faith.
* A retained SHA-1 repository, against which `S1` is confirmed directly (see the
  section on confirming against a retained SHA-1 repository).

Because the snapshot records only repository state, verification is not tied to
the tool that performed the migration. A verifier is free to check the migration
with a different tool than the one that produced it, and doing so is what
strengthens the guarantee. For adversarial assurance a verifier must not blindly
trust a translation table produced by the same tool that performed the migration
(see Security). A tool-supplied mapping is an optimization for the honest case.
Independent, deterministic recomputation, ideally with a distinct
implementation, is the fallback that provides the full guarantee.

### Migration tools and what must be confirmed for each

Migrating a repository from SHA-1 to SHA-256 is not the job of a single tool, and
the tools that do it today differ in ways that directly affect verification.
Making the transition safe and independently checkable is what enables
cryptoagility in practice: a project can move off a weakening hash algorithm
without having to trust one migration tool, and the same snapshot mechanism
applies to a future transition to whatever algorithm comes after SHA-256.

* **Git's native transition.** Git's experimental SHA-256 support, combined with
  compatibility mode, keeps a bidirectional mapping between each object's SHA-1
  and SHA-256 names and preserves object content as far as the transition
  specification allows. The SHA-256 name of an object is the canonical
  hash-function-transition name, obtainable with
  `git rev-parse --output-object-format=sha256`.
* **git-sync `convert-sha256`.** git-sync produces a fresh SHA-256 repository by
  re-hashing every reachable object under SHA-256 in a memoized depth-first walk
  (see
  [git-sync SHA-256 conversion](https://github.com/entireio/git-sync/blob/main/docs/convert-sha256.md)).
  It does not rely on Git's compatibility mapping. It offers a `--check` mode that
  runs `git fsck --full`, and it rewrites SHA-1 hashes embedded in commit and tag
  messages to their SHA-256 equivalents and strips GPG signatures, since those
  signatures cannot verify once the bytes change. By default it also records the
  pre-conversion SHA-1 name of each commit in a `refs/notes/sha1-origin` note.
  That note adds a reference that is absent from the pre-migration state, so for
  snapshotting it must be suppressed or stripped before `S2` is taken. Any mapping
  worth keeping between SHA-1 and SHA-256 should live outside the repository as an
  out-of-band artifact rather than as an added ref.

These two tools illustrate that the SHA-256 identifier assigned to an object is
tool-dependent once a tool alters object content, for example by rewriting hash
strings in messages or removing signatures. A tool that changes object bytes
beyond the mechanical hash substitution does not, in general, produce Git's
canonical hash-function-transition name. The verification workflow assumes a
translation oracle that maps each SHA-1 name to the SHA-256 name actually used in
`S2`. That oracle must come from, or be validated against, the specific tool that
performed the migration, and cannot be assumed to be Git's canonical mapping for
every tool.

Before a snapshot pair produced around a given tool can be trusted, the following
must be tested and confirmed for that tool.

1. **Translation model.** Determine whether the tool's SHA-256 names are Git's
   canonical hash-function-transition names or a tool-specific mapping, and where
   the authoritative SHA-1 to SHA-256 mapping comes from (Git compatibility mode,
   an out-of-band mapping artifact, or independent recomputation). The mapping
   must not be sourced from state the migration added to the repository itself.
   The correspondence check in the verification workflow is only valid against
   the mapping the tool actually used.
1. **Content transformations.** Enumerate every transformation the tool applies
   beyond substituting hashes: message rewriting, signature stripping, submodule
   handling, and any normalization. Confirm each transformation is intended,
   documented, and reversible or otherwise accountable, so that "faithful" is
   defined precisely for that tool rather than assumed to mean byte-identical
   payloads.
1. **Determinism.** Confirm the conversion is deterministic, so that an
   independent re-run, or a second tool, reproduces the same SHA-256 names from
   the same SHA-1 source. Determinism is what lets the adversarial fallback of
   independent recomputation reproduce `S2` without trusting the original
   migrator, and it is why `S2` records the migration tool, its version, and its
   binary hash: a verifier can obtain the same tool and re-run it to reproduce the
   result.
1. **Scope and completeness.** Confirm the tool migrates every reference and
   object in the snapshot scope, including gittuf's own references
   (`refs/gittuf/*`), notes, tags, and any replace references, and that it fails
   closed on objects it cannot resolve (for example unresolvable submodules)
   rather than silently dropping them.
1. **Baseline retention.** Confirm a baseline exists against which `S1` can be
   confirmed independently: the original SHA-1 repository is retained (for
   git-sync, via `--keep-source-objects`), or an out-of-band mapping file back to
   SHA-1 is preserved. The baseline must be kept outside the migrated repository.
   A baseline recorded as an in-repo reference or note (such as git-sync's default
   `refs/notes/sha1-origin`) changes the migrated state and must be avoided or
   stripped. Without a retained baseline the pre-migration state cannot be
   re-derived later.
1. **Post-migration integrity.** Confirm the resulting SHA-256 repository is
   well-formed, for example with `git fsck --full` (git-sync's `--check`), so
   that a structurally broken migration is caught before `S2` is signed.
1. **gittuf metadata survival.** Confirm the RSL, policy metadata, and
   attestations survive the migration as valid SHA-256 objects and that gittuf
   can read and verify them afterward (gittuf's SHA-256 support,
   [gittuf/gittuf#1472](https://github.com/gittuf/gittuf/pull/1472)), and that
   `S2`'s RSL tip corresponds to `S1`'s RSL tip under the confirmed mapping.

### Guarantees provided by a verified snapshot pair

When `S1` and `S2` both pass the checks above, the following hold for everything
in scope (the listed references and the objects reachable from them).

* No reference was added or removed. The reference set is identical in `S1` and
  `S2`. A reference present in only one of them, or a reference whose tip does
  not correspond across the two algorithms, fails verification.
* Every reference points to a reconstructible object. Each SHA-256 tip in `S2`
  corresponds to a SHA-1 object that can be reconstructed in the SHA-1
  repository, and each SHA-1 tip in `S1` corresponds to the SHA-256 object
  recorded in `S2`. No reference was repointed to an object that did not exist,
  in reconstructible form, before the migration.
* The reachable object graph is unchanged. By the Merkle property, correspondence
  of every reference tip transitively fixes the entire reachable closure. No
  reachable commit, tree, blob, or tag was substituted, added, or removed.
* gittuf's own state is carried faithfully. Because gittuf's references are in
  scope, the RSL, policy metadata, and attestations are subject to the same
  guarantees. The RSL tips recorded in the two snapshots tie the migration into
  gittuf's activity log, so no RSL entry was silently introduced or dropped
  during the transition.

The snapshot does not establish that the pre-migration history was itself
trustworthy, nor does it cover anything outside the scoped references. These
limits are enumerated in the Security section.

### Confirming against a retained SHA-1 repository

A common migration pattern is to convert a repository to SHA-256 while leaving a
copy of the original SHA-1 repository in place, for example an archived clone, a
mirror, or a backup. In this case the retained SHA-1 repository is itself the
ground truth, and the pre-migration snapshot can be confirmed directly against
it without relying on the migrated repository's compatibility-mode translation at
all:

1. In the retained SHA-1 repository, confirm that the reference set and each
   reference tip match those recorded in `S1`.
1. Verify the signatures on `S1`.

This establishes `S1` as a faithful, signed description of the original
repository using only standard Git and signature tooling. Comparing `S2` against
this confirmed `S1` then shows that the migration preserved that state. Retaining
both the original repository and the signed pre-migration snapshot therefore lets
any user confirm the transition with minimal trust in the migration tooling.

### Preservation of commit and tag signatures across the transition

Migrating from SHA-1 to SHA-256 rewrites the bytes of every object. A commit or
tag signature (`gpgsig`) is computed over the object's payload, which in a SHA-1
repository names its tree, parents, or target by SHA-1. The migrated SHA-256
object has different bytes, so the original signature does not verify against the
SHA-256 form of the object. The migration cannot produce a valid SHA-256-native
signature for historical objects, because doing so would require the original
signers to re-sign with their private keys.

The authenticity of historical commits and tags is therefore not lost, but the
guarantee that is retained is narrower than it may first appear: these signatures
remain verifiable only against the SHA-1 representation of each object, which
stays reconstructible under Git's compatibility mode and in any retained SHA-1
repository. Verifiers, including gittuf's own verification workflow, must check
historical object signatures against the SHA-1 representation rather than
expecting a native SHA-256 signature.

The snapshot adds a fresh, SHA-256-native signature over the post-migration state
as a whole. This does not re-establish per-object signatures, but it provides a
newly signed, verifiable anchor for the repository's state at the moment of
migration, attributable to whoever performed or witnessed it. Where per-object
SHA-256-native authenticity is required going forward, the original signers must
re-sign the migrated objects. That re-signing is out of scope for this GAP.

## Motivation

By default, Git uses the SHA-1 hash algorithm to calculate unique identifiers.
Due to known weaknesses with SHA-1, the Git community has proposed moving to
SHA-256. Experimental support and a compatibility mode exist, but migrating an
existing repository remains a high-risk, all-at-once event: every object
identifier and every reference changes simultaneously. A malicious or buggy
migration could substitute a tree or blob, drop or add objects, or repoint a
reference, and because every identifier legitimately changes during a migration,
a naive observer cannot easily distinguish a faithful migration from a tampered
one.

gittuf already tracks repository state through the RSL and records signed,
multi-party attestations. It is therefore well positioned to capture a signed
snapshot of repository state before and after a migration and to make the
transition independently verifiable. Users gain assurance that the post-migration
repository is content-identical to the pre-migration repository, backed by
signatures they can verify themselves.

The deeper goal is cryptoagility. A repository must be able to move off a hash
algorithm once that algorithm weakens, and it should be able to do so again for
whatever algorithm follows SHA-256. That is only safe if the migration itself can
be trusted, and it is only practical if no single migration tool has to be
trusted. By recording signed, tool-independent snapshots that any party can
verify with any conforming tool, this GAP turns a rare, high-risk transition into
a routine, auditable operation, which is what makes ongoing cryptoagility
attainable rather than a one-time gamble.

## Reasoning

### Snapshots instead of a continuous SHA-1 to SHA-256 mapping

An earlier iteration of this GAP proposed that gittuf recompute and permanently
maintain a SHA-1 to SHA-256 mapping for every object in the repository. This has
been dropped. Git's compatibility mode already maintains the bidirectional
object translation for interoperability, so duplicating it in gittuf is
redundant and unbounded. Additionally, a migration transitions the entire
repository, including gittuf's own references and objects, to the new algorithm.
There is no residual dual-hash state for gittuf to carry once a migration
completes. A snapshot is a bounded, event-scoped artifact rather than a permanent
parallel store, and it directly answers the question that matters during a
migration: did the repository's content survive the transition unchanged?

### Retaining the pre-migration snapshot

The pre-migration snapshot is expressed in the old algorithm and captures the
ground-truth state before any rewrite occurred. If it were discarded after the
migration, the baseline needed to judge the migration would be lost. Retaining
it, signed and independent of the migration tool, preserves the ability to audit
the transition at any future time.

### Independent verifiability

Snapshots are plain signed documents rather than gittuf-internal structures, so
that any party can verify them with standard signing tools and can add their own
signature. This lets a migration be corroborated by multiple independent
observers, which is valuable because the migration is a rare, high-impact event
where a single tool's word should not be the only assurance.

### Independence from any single migration or verification tool

The snapshot captures repository state, not the process that produced it, so the
design does not privilege one migration tool or one verification tool. The
migration may be carried out by Git's experimental transition support or by any
other tool that implements Git's hash function transition. Likewise, the SHA-1 to
SHA-256 translation that verification depends on can be obtained from Git, from
an independent reimplementation of the transition, or from a retained SHA-1
repository. This separation is deliberate. It keeps gittuf aligned with the
transition specification rather than with a particular binary, and it lets a
migration performed by one tool be verified by a different one, so that no single
tool's correctness has to be taken on faith.

### Recording migration provenance for repeatability

Provenance is recorded at two levels, because it describes two different facts.
The migration event has a single provenance, the migrator's claim of which tool,
version, and binary produced the result, and it is recorded in `S2`'s `migration`
block, attributed to the actor that ran it. Reproduction has a provenance per
party, recorded alongside each signer's attestation rather than in the shared
body. Keeping the two apart means a signature over `S2` attests only the state,
while the tool a party used to confirm it is that party's separate, attributable
claim. A witness who observed the state without reproducing it does not
implicitly vouch for the migrator's tool, and a verifier that reproduced the
result with a different tool can say so without contradicting the recorded
migration claim.

This is not a substitute for the content checks, which stand on their own, but it
makes the transition repeatable and cheap to audit. Given deterministic
conversion, a verifier who obtains the tool named in the `migration` block at the
same version and confirms its binary hash can re-run the migration and expect the
same SHA-256 tips. Because reproduction records are per-signer, several parties
can corroborate the same `S2` with distinct tools, and agreement across those
independent reproductions carries stronger assurance than a single unrepeatable
run. A binary hash pins the exact tool but does not by itself guarantee
bit-for-bit reproducibility across platforms or toolchains, so it complements,
rather than replaces, independent recomputation.

Provenance must not come at the cost of changing what is being attested. A
migration tool must not write its mapping or provenance back into the migrated
repository as a new reference or note, because that would add state that is
absent from the pre-migration snapshot and break the requirement that the
reference set be identical across the two snapshots. Provenance belongs in the
snapshot's `migration` block, and any retained mapping belongs in an out-of-band
artifact, not in an added ref.

### Why reference tips, and not commit-only re-hashing, are compared

A tempting shortcut is to record only commit tips and re-hash the commit objects
under SHA-256. This has a blind spot. A collision in a tree object is dangerous:
the commit object can remain unchanged while pointing to a malicious version of
the tree, and a hash taken only over the commit would not detect it. By anchoring
verification on the full reachable closure (via Git's whole-graph translation
under compatibility mode, with independent recomputation as the fallback), a
substituted tree changes the translated tip and breaks correspondence between
the snapshots. This is why verification relies on the Merkle closure rather than
on re-hashing commit objects alone.

### Forward compatibility with Git's SHA-256 support

By relying on Git's transition and compatibility mode rather than inventing a
separate mapping, gittuf stays aligned with whatever migration and interoperation
techniques Git provides. The SHA-256 identifiers referenced in snapshots are
Git's own identifiers, so gittuf introduces no divergent notion of an object's
SHA-256 name.

## Backwards Compatibility

This GAP does not break the backwards compatibility of gittuf's design. Snapshots
are a new attestation type recorded in gittuf metadata. Repositories that never
migrate never need to produce a snapshot, and the addition of the snapshot type
does not alter existing gittuf workflows.

## Security

A detailed security analysis is necessary before this GAP is implemented. This
section states what a verified snapshot pair does and does not establish, so that
the guarantee is not overstated in practice.

### What a verified snapshot pair establishes

A verified pair of snapshots proves that nothing in scope changed during the
migration window. It provides the guarantees enumerated under "Guarantees
provided by a verified snapshot pair": no reference was added or
removed, every reference tip is reconstructible and corresponds across the two
algorithms, the entire reachable object graph is preserved, and gittuf's own
state (RSL, policy, attestations) is carried faithfully. When the original SHA-1
repository is retained, these can be confirmed with minimal trust in the
migration tool, using only standard Git and signature tooling.

### What a verified snapshot pair does not establish

* The snapshot does not prove the pre-migration history was trustworthy. If a
  colliding or otherwise malicious object was introduced before `S1` was taken,
  the migration faithfully preserves that state and the snapshots still verify.
  The guarantee is about the fidelity of the transition, not the integrity of
  prior history.
* The snapshot does not create SHA-256-native signatures for historical objects.
  Original commit and tag signatures remain verifiable only against the SHA-1
  form of each object, as covered in the discussion of commit and tag signature
  preservation above. Per-object authenticity does not migrate to SHA-256 unless
  the original signers re-sign.
* The snapshot says nothing about out-of-scope state. Unreachable objects, the
  reflog, and any un-listed notes or replace references are not covered and must
  not be assumed preserved.
* The snapshot does not, by itself, vouch for the migration tool's translation. A
  verification that trusts Git's compatibility-mode translation trusts a table
  that may have been produced by the same tool that performed the migration. A
  malicious migrator could emit a translation that presents a tampered object as
  the faithful translation of an original.

### Additional considerations

* For adversarial assurance the verifier must not rely on the supplied
  translation table alone. It must independently recompute SHA-256 names from the
  retained pre-migration objects, or confirm `S1` against a retained SHA-1
  repository. This requires that the pre-migration object content remain
  available, which compatibility mode preserves by keeping objects addressable
  under both algorithms.
* Snapshots are signed and anchored in the RSL. Recording the RSL tip in each
  snapshot ensures that any RSL entry introduced during the migration window is
  visible when the two snapshots are compared. The migration should be bracketed
  so that no unrelated pushes are interleaved, or any such push must appear as an
  RSL entry that verification can account for.
* A migration tool must not add references, notes, or objects to the migrated
  repository beyond the faithful translation of what already existed. Provenance
  and mapping conveniences that some tools write into the repository (for example
  git-sync's default `refs/notes/sha1-origin`) introduce a reference absent from
  the pre-migration state and cause the identical-reference-set check to fail.
  Such data must be suppressed, stripped before `S2` is taken, or kept as an
  out-of-band artifact. Migration provenance belongs in the snapshot's
  `migration` block, not in the repository.
* The migration tool's binary hash recorded in `S2` pins the exact tool but does
  not guarantee bit-for-bit reproducibility across platforms or toolchains. It
  supports repeatability and attribution. It does not replace independent,
  deterministic recomputation for adversarial assurance.
* The migration block records the migrator's claim, not a verified fact. A
  signature over `S2` attests the recorded state, and only signers that attach a
  reproduction record are asserting that they re-derived the result. Verification
  must not treat the presence of a migration block as evidence that the migration
  was faithful.
* The `invocation` in the `migration` block, along with the `performedBy` and
  `reproducedBy` identities, is published and retained under signature. It must be
  normalized to avoid leaking local filesystem paths, credentials, or private
  URLs. Record only what is needed to reproduce the migration.

## Prototype Implementation

A prototype of the earlier mapping-based approach was proposed in
https://github.com/gittuf/gittuf/pull/105. That approach has been superseded by
the snapshot approach described here, and the prototype is retained only for
historical reference.

## Changelog

* July 28th, 2026: refocused the GAP from maintaining a continuous SHA-1 to
  SHA-256 object mapping onto capturing a signed, independently verifiable
  repository snapshot before and after a migration. The pre-migration snapshot is
  retained after the migration, and gittuf relies on Git's hash function
  transition for hash translation rather than maintaining its own mapping. The
  GAP is written against the transition rather than a single tool, so the
  migration and its verification may each be performed by any conforming tool.
  Added git-sync's `convert-sha256` as a concrete example of an existing
  migration tool, mapped the properties that must be tested and confirmed for a
  given migration tool, and framed the GAP around enabling cryptoagility. Added a
  two-tier migration provenance model to support repeatability: the migration
  event's provenance (who performed it, tool, version, binary hash, invocation)
  is recorded as the migrator's claim in the post-migration snapshot's `migration`
  block, while reproduction provenance is recorded per signer as an optional
  reproduction record attached to each attestation. Required that a migration not
  add new references or notes to the repository (mappings and provenance must stay
  out-of-band or in the snapshot), so the identical-reference-set guarantee holds.
* January 20th, 2025: moved from `/docs/extensions` to `/docs/gaps` as GAP-1

## References

* [Git Hash Function Transition](https://git-scm.com/docs/hash-function-transition/2.48.0)
* [Git `--output-object-format` and compatibility mode](https://git-scm.com/docs/git-rev-parse)
* [gittuf: support SHA-256 object format (gittuf/gittuf#1472)](https://github.com/gittuf/gittuf/pull/1472)
* [git-sync: SHA-1 to SHA-256 conversion](https://github.com/entireio/git-sync/blob/main/docs/convert-sha256.md)
* [SHAttered](https://shattered.io/)
