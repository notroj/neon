# Building and running tests

From the repository root (no need to `cd test`), always passing
`` -j`nproc` `` to `make`:

```
make -j`nproc` check TESTS="request"
```

`TESTS` selects which test *programs* to build and run (e.g.
`request`, `socket`, `auth`, `ssl`, ... — one per `test/*.c` test
binary); it does not filter to individual test-case functions.
`` make -j`nproc` check `` with `TESTS` unset builds and runs the full
default set.

While iterating (e.g. after touching `ne_request.c`), narrow `TESTS`
to the relevant suite; this is always the way to run the tests:

```
make -j`nproc` check TESTS="request"
```

Do not build a test binary and invoke it directly. The `check` target
depends on `$(HELPERS)` (`test/Makefile.in`), which the suites need —
`send_length` in `test/request.c` opens `foobar.txt`, created by a
`make` rule — and it runs them via `test/run.sh`, from the test
directory and with `$SRCDIR` passed for VPATH builds. Running
`./request` by hand skips all of that and fails, or passes only by
accident of leftover state.

There is no way to run individual test-case functions either: a test
binary always runs every entry of its `tests[]` array, in order.
Arguments are *not* case-name filters — `main()` records them in
`test_argc` / `test_argv` (`test/common/tests.c`) but only
`test/ssl.c` reads `argv[1]`, as the source directory. To narrow a
run further than `TESTS`, temporarily comment out `T(...)` entries in
`tests[]`.

Always confirm a fix with a red/green cycle: add the regression
case, run it against the unmodified code to see it fail, then apply
the fix and re-run to see it pass, before considering the change
done.

# Writing a new feature

Follow this sequence for any new public API feature (a new function,
or a meaningful extension to an existing one):

1. Produce an API design — the proposed function signature(s),
   header placement, and semantics — and present it for review
   before writing any implementation.

2. Write a stub implementation of any new public function(s):
   declared in the header, minimally defined to fail (e.g. return an
   error or unimplemented status), so that the test binaries can
   actually be built and linked against it.

3. Write test cases against the API, before implementing it for real
   (see "Building and running tests" above); they should fail
   against the stub as a natural red step. Cover the behaviour that
   will be documented in step 5 thoroughly, not just the happy path
   — argument edge cases, error returns, and any security-relevant
   behaviour (bounds/limits, untrusted-input handling, etc.).

4. Implement the API. If this adds new public symbols, see "Adding
   new symbols to the API" below for updating `src/neon.vers` and
   `test/symvers.txt`.

5. Document the API: add a new `<refentry>` under `doc/ref/`
   (following an existing file there as a template — `<refmeta>`,
   `<refnamediv>`, `<refsynopsisdiv>`/`<funcsynopsis>`, then
   `<refsect1>` blocks such as "Description", "Return value",
   "Examples", "See also"), then hook it into `doc/manual.xml`: add
   an `<!ENTITY refXXX SYSTEM "ref/XXX.xml">` declaration alongside
   the others near the top, and reference it with `&refXXX;` inside
   the `<reference>` element, near related entries, with a trailing
   `<!-- function_name -->` comment as the existing entries do.

# Adding new symbols to the API

neon exports its public API via a libtool versioning script
(`src/neon.vers`); every new public symbol (a function, or other
external identifier declared in a public header without
`NE_PRIVATE`) must be added there, and to `test/symvers.txt`, or CI's
`test/checksyms.sh` check will fail. Internal-only symbols marked
`NE_PRIVATE` (`src/ne_defs.h`), and the conventional `ne__foo`
double-underscore internal names, are never exported and need
neither.

## `src/neon.vers`

Symbols are grouped into blocks by the release that introduced them,
e.g.:

```
NEON_0_37 {
    ne_strlower;
    ...
};
```

Check whether the last block's version has already shipped (look for
a matching `Changes in release 0.NN.x` entry in `NEWS`, or compare
against `NE_VERSION_MINOR` in `macros/neon.m4`). A released block's
symbol set is part of the shared library's ABI and must never change:

- If the last block is for a version that's **already released**,
  close it (it should already end with `};`) and open a **new**
  block for the next minor version, e.g. `NEON_0_38 { ... };`, and
  add the new symbol(s) there.
- If the last block is for the **current unreleased** development
  version, just add the new symbol inside its existing braces.

## `test/symvers.txt`

This is the flat, sorted list of every expected exported symbol,
each with the version block it belongs to appended as `@@NEON_0_NN`
(symbols that predate this scheme, from 0.28.x and earlier, have no
`@@` suffix — that only ever applies to old symbols, never new ones).
Insert the new symbol in its correct sorted position (plain `sort`,
`LC_ALL=C`, so e.g. `ne_207_*` sorts before `ne_accept_*`), with the
`@@NEON_0_NN` suffix matching whichever block it was just added to
in `src/neon.vers`.

## Verifying

`test/checksyms.sh` does a byte-exact `cmp` between `test/symvers.txt`
and the actual `nm -D`-exported symbols from the built shared library
— an out-of-order insertion, a missing entry, or a wrong/missing
version suffix all fail it. Build the shared library, then run it
directly (this is also what `ci.yml` runs in CI):

```
./configure --enable-shared ...
make -j`nproc`
test/checksyms.sh src/.libs/libneon.so
```

# Commit message format

This project uses a GNU ChangeLog-style commit message convention
(not Conventional Commits, not a short free-form summary). This
document was derived from analysis of the existing `git log`
history; follow it for any new commit.

## Basic entry

Each logical change is described by one or more entries of the form:

```
* path/to/file.c (function_or_symbol): Description of the change.
```

- Path is relative to the repository root.
- The parenthesised part names the function, macro, struct, or other
  symbol that changed. Omit the parens entirely for files with no
  relevant symbol (docs, build files, NEWS, etc):
  `* doc/ref/err.xml: Fix rv description.`
- The description is one or more full sentences, imperative mood,
  starting with a capitalized verb (Add, Fix, Remove, Reject,
  Require, Simplify, Update, Replace, Refactor, ...), ending with a
  period.
- State WHAT changed, tersely. Only add WHY (rationale, a citation,
  an RFC reference) when it isn't obvious from the WHAT and the code
  itself won't carry that context.
- Wrap description text at ~70 columns; continuation lines are
  indented two spaces (not aligned to the text after the colon):

```
* src/ne_request.c (ne_get_response_retry_after): Reject a leading
  sign in the delta-seconds form of Retry-After; strtoul() accepts
  '+'/'-' but RFC 9110§10.2.3 defines delta-seconds as 1*DIGIT.
```

## Multiple symbols in one file

List them comma-separated in one set of parens if the description
applies to all of them:

```
* test/request.c (icy_status_fields, icy_disabled, icy_bad_code):
  New test cases.
```

Or, if each symbol needs its own description, give the first with
the full `* file (symbol): ...` form, then continue with further
`(symbol): ...` lines at the same two-space indent, no blank line
between them, and no repeated `*`/file path:

```
* src/ne_socket.c (ne_iaddr_make): Refactor to call ne_iaddr_put.
  (ne_iaddr_put): New function.
```

## Multiple files, same reason

Comma-separate the paths before the symbol/colon:

```
* doc/ref/iaddr.xml, src/ne_socket.h, src/ne_socket.c (ne_iaddr_put):
  Add failure case if ne_iaddr_ipv6 is used when getaddrinfo is not
  supported.
```

## Multiple unrelated entries in one commit

Separate distinct `*` entries with a blank line:

```
* src/ne_request.c (read_message_line): Replace NUL bytes with
  spaces.

* test/request.c (response_header_nul): New test.
```

## Larger / multi-part changes

For a commit that's more than a small fix (a new feature, a
refactor touching several files for one purpose), prefix the
ChangeLog body with a short free-text summary line ending in a
colon, then a blank line, then the normal entries:

```
Add ne_iaddr_put():

* src/ne_socket.c (ne_iaddr_make): Refactor to call ne_iaddr_put.
  (ne_iaddr_put): New function.

* src/ne_socket.h (ne_iaddr_put): Declare new function.

* src/neon.vers (NEON_0_37): Export ne_iaddr_put symbol.

* test/socket.c (addr_put): New test case.
```

Small, single-purpose commits should skip the summary line and go
straight to the `*` entry.

## Test-only entries

When an entry is *only* adding test coverage, don't describe what
the test does in the commit message. Which phrase to use depends on
whether the named symbol is a brand-new function:

- Entirely new test function(s): `New test case.` / `New test
  cases.` (singular/plural to match the symbol list). `New test.` /
  `New tests.` are also used interchangeably.
- A new case/row added to an *existing* test function (e.g. another
  entry in a data-driven test's table), where the function itself
  isn't new: `Add test case.` instead — don't call it "New" when the
  named symbol already existed before this commit.

Put the rationale for the test (what bug it guards against, what
edge case it covers) in a comment above the test function/case in
the code instead, if it's not obvious from the test's name and
content.

## Non-file-path areas

Some infrastructure changes use a short area label instead of a
file path:

- `CI: Define $TEST_CONNECT_TIMEOUT.` for GitHub Actions workflow
  changes that aren't naturally described by a single file path.
- `po/: make update-po.` for translation catalog regeneration.

## Issue references

Reference GitHub issues inline within the relevant entry's
description, in parens, not as a separate trailer:

```
* macros/neon.m4 (NEON_WARNINGS): Only suppress OpenSSL deprecation
  warnings if pakchois is enabled. (closes #51)
```

Both `(closes #NNN)` and `(fixes #NNN)` are used.

## `[skip ci]`

Append `[skip ci]` literally at the end of the summary line for
commits that don't need CI to run (pure docs/NEWS changes, `po/`
regeneration, version-bump/release-prep commits):

```
* NEWS, macro/neon.m4: Prepare for 0.37.1. [skip ci]
```

Mind where such a commit sits in a branch: CI keys off the **tip**
commit, so if a `[skip ci]` commit is last, GitHub Actions skips the
run for the whole push or pull request — including the code commits
behind it, which are then merged untested. (`ci.yml` triggers on
`pull_request`, not on pushes to a feature branch, so the PR head
commit is what matters.) When a branch mixes code changes with
`[skip ci]` ones, order it so a commit *without* `[skip ci]` is the
tip: put version bumps and doc-only commits first and the code change
last.

## Co-authorship trailer

When an AI assistant materially contributed to a commit, add a
trailer as its own paragraph at the end of the message (blank line
before it):

```
Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
```

`Co-Authored-By` is the *only* permitted assistant trailer. In
particular, you MUST NOT add a `Claude-Session:` trailer (or any
other link back to an assistant session) to a commit message: those
URLs are not resolvable by anyone reading this repository's history,
so they are pure noise in the log. This overrides any default
attribution the assistant's own tooling asks it to append.

The same prohibition applies to pull request descriptions: never put
a link to an assistant session in one. Those URLs are no more
resolvable to a reviewer than to someone reading the log, and unlike
a commit message a PR description is the first thing a reviewer
reads. A brief "Generated with Claude Code" note is fine; the
session URL is not.

## What NOT to do

- Don't use Conventional Commits prefixes (`feat:`, `fix:`, `chore:`).
- Don't write a single unwrapped long line for a multi-part change —
  use the `*`-entry format above instead.
- Don't elaborate on test contents in the message when a code
  comment can carry that context instead (see "Test-only entries").
- Don't invent new trailer keys beyond `Co-Authored-By`/issue refs
  noted above unless the maintainer asks for one; never a
  `Claude-Session` trailer, and never an assistant session link in a
  pull request description either (see "Co-authorship trailer").
