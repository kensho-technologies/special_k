#!/usr/bin/env bash
# Copyright 2020-present Kensho Technologies, LLC.

# Fail on first error, on undefined variables, and on errors in a pipeline.
set -euo pipefail

# Ensure that the "**" glob operator is applied recursively.
# Make globs that do not match return null values.
shopt -s globstar nullglob

# Make sure the current working directory for this script is the root directory.
cd "$(git -C "$(dirname "${0}")" rev-parse --show-toplevel )"

ensure_file_has_copyright_line() {
    filename="$1"

    lines_to_examine=2
    copyright_regex='# Copyright 2[0-9][0-9][0-9]\-present Kensho Technologies, LLC\.'

    file_head=$(head -"$lines_to_examine" "$filename")
    set +e
    echo "$file_head" | grep --regexp="$copyright_regex" >/dev/null
    result="$?"
    set -e

    if [[ "$result" != "0" ]]; then
        echo "The file $filename appears to be missing a copyright line, file starts:"
        echo "$file_head"
        echo 'Please add the following at the top of the file (right after the #! line in scripts):'
        echo -e "\n    # Copyright $(date +%Y)-present Kensho Technologies, LLC.\n"
        exit 1
    fi
}

# Check every python file in the package's source directory.
for filename in ./special_k/**/*.py; do
    ensure_file_has_copyright_line "$filename"
done
