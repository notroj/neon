#!/bin/sh
# Summarise gcov coverage of the library sources as a Markdown table on
# stdout, worst-covered file first.  Used by .github/workflows/coverage.yml
# to populate the job summary, but equally usable by hand:
#
#   ./configure CFLAGS="-g -O0 --coverage" LDFLAGS="--coverage" ...
#   make && make check
#   sh test/ci-coverage-report.sh
#
# Run from the top of the build tree; pass the source directory as $1 for
# a VPATH build (default: the build tree itself).

set -e

srcdir=${1-.}

# gcov prints a block per file contributing to an object -- headers
# included -- and an overall total at the end of the run, so pick out
# only the block for the file being asked about.
rows=`
for src in "$srcdir"/src/*.c; do
    name=\`basename "$src"\`
    gcov -b -o src "$src" 2>/dev/null | tr -d "'" | awk -v name="$name" '
      $0 ~ "^File (.*/)?" name "$" { inblock = 1; next }
      /^Creating / { inblock = 0 }
      inblock && /^Lines executed:/ { split($0, a, "[:%]"); pl = a[2]+0; nl = $NF+0 }
      inblock && /^Taken at least once:/ { split($0, a, "[:%]"); pb = a[2]+0; nb = $NF+0 }
      END { if (nl) printf "%.2f %.2f %d %d %s\n", pl, pb, nl, nb, name }
    '
done | sort -n
`

if test -z "$rows"; then
    echo "## Coverage"
    echo
    echo "No coverage data found: was the tree configured with \`--coverage\`?"
    exit 0
fi

echo "$rows" | awk '
  BEGIN {
    print "## Coverage"
    print ""
    print "| File | Lines | Branches taken |"
    print "|---|---:|---:|"
  }
  {
    tl += $3; cl += $3 * $1 / 100
    tb += $4; cb += $4 * $2 / 100
    printf "| `src/%s` | %.1f%% of %d | %.1f%% of %d |\n", $5, $1, $3, $2, $4
  }
  END {
    # Weighted from the per-file percentages gcov reports, so the total
    # is accurate to well under a line per file rather than exact.
    if (tl) printf "| **total** | **%.1f%% of %d** | **%.1f%% of %d** |\n", \
                   100 * cl / tl, tl, tb ? 100 * cb / tb : 0, tb
    print ""
    print "Per-line detail is in the `coverage-gcov` artifact."
  }
'
