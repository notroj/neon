# Building and running tests

From the repository root (no need to `cd test`):

```
make check TESTS="request"
```

`TESTS` selects which test *programs* to build and run (e.g.
`request`, `socket`, `auth`, `ssl`, ... — one per `test/*.c` test
binary); it does not filter to individual test-case functions.
`make check` with `TESTS` unset builds and runs the full default set.

To run only specific test-case functions while iterating (e.g. after
touching `ne_request.c`), build the one relevant binary and then
invoke it directly with the case names as arguments — the test
harness filters to just the named cases when given any:

```
make -C test request
test/request icy_bad_code retry_after
```

Always confirm a fix with a red/green cycle: add the regression
case, run it against the unmodified code to see it fail, then apply
the fix and re-run to see it pass, before considering the change
done.

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

## Co-authorship trailer

When an AI assistant materially contributed to a commit, add a
trailer as its own paragraph at the end of the message (blank line
before it):

```
Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
```

## What NOT to do

- Don't use Conventional Commits prefixes (`feat:`, `fix:`, `chore:`).
- Don't write a single unwrapped long line for a multi-part change —
  use the `*`-entry format above instead.
- Don't elaborate on test contents in the message when a code
  comment can carry that context instead (see "Test-only entries").
- Don't invent new trailer keys beyond `Co-Authored-By`/issue refs
  noted above unless the maintainer asks for one.
