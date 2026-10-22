#!/bin/sh
# Looks for private data before it reaches a public remote: secrets, host
# addresses, personal paths, local databases. Run it instead of a bare push:
#
#   scripts/leak-check.sh && git push
#
# It scans the working tree exactly as a commit would see it (untracked files
# included, gitignored ones excluded), plus whatever is already staged.
# Patterns are deliberately few and specific: a clean run has to mean nothing,
# otherwise people stop running it. Where a hit is known-safe, narrow the glob
# or the regex here rather than deleting the pattern.
set -eu

cd "$(git rev-parse --show-toplevel)"

# Fixtures and vendored code legitimately contain keys, certificates and
# example addresses from RFC 1918 ranges.
skip() {
    grep -vE '(^|/)(testdata|fixtures|tests|vendor|js)/|\.min\.js'
}

# The placeholders bootstrap replaces in the tracked config templates, and the
# generic example usernames that upstream tests and docs use.
known() {
    grep -vE 'CHANGE_ME_ADMIN_TOKEN|REPLACE_ME_WITH_A_REAL_BCRYPT_HASH|(Users|home)/(user|example|sample|admin|foo|bar)/'
}

# label|pathspec|extended regex, one per line. The pathspec keeps patterns off
# file types where they only produce noise (Go code, vendored data).
patterns() {
    cat <<'EOF'
private key|*|-----BEGIN [A-Z ]*PRIVATE KEY-----
ssh key|*|ssh-(rsa|ed25519) AAAA[A-Za-z0-9+/]{40,}
cloud access key|*|(AKIA|ASIA)[0-9A-Z]{16}
slack/github token|*|(xox[baprs]|ghp|gho|github_pat)-[0-9A-Za-z-]{16,}
bearer token|*|[Bb]earer +[A-Za-z0-9+/_-]{32,}
private host address|*.yaml *.yml *.md *.sh *.json *.txt|(^|[^0-9.])(10\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3})\.[0-9]{1,3}([^0-9/]|$)
bcrypt password hash|*.yaml|password_hash: *["']?\$2[aby]\$
admin token|*.yaml|admin_token: *["']?[A-Za-z0-9+/_-]{20,}
api credential|*.yaml|(login|password|token|api_key): *["']?[A-Za-z0-9+/_-]{24,}["']?$
personal home path|*.yaml *.yml *.md *.sh *.js *.json|(^|[^A-Za-z0-9._-])/(Users|home)/[a-z][a-z0-9_-]{2,}/
EOF
}

found=0

report() {
    label="$1"
    hits="$2"
    [ -n "$hits" ] || return 0
    found=1
    printf '%s\n' "--- $label"
    printf '%s\n' "$hits"
}

scan_tree() {
    regex="$1"
    shift
    git grep -InE --untracked -- "$regex" -- "$@" 2>/dev/null | skip | known || true
}

text=""

scan_staged() {
    printf '%s\n' "$text" | grep -E -- "$1" | known || true
}

# set -f: the pathspec field must reach git as a glob, not as the names of the
# files the shell happens to find in the current directory.
set -f
# 1. content of every file a commit from here could contain
while IFS='|' read -r label pathspec regex; do
    [ -n "$label" ] || continue
    # shellcheck disable=SC2086  # the pathspec field is meant to be several args
    set -- $pathspec
    report "$label (working tree)" "$(scan_tree "$regex" "$@")"
done <<EOF
$(patterns)
EOF
set +f

# 2. staged content, which can differ from the working tree
text=$(git diff --cached -U0 --diff-filter=AM 2>/dev/null | grep '^+[^+]' | skip || true)
if [ -n "$text" ]; then
    while IFS='|' read -r label pathspec regex; do
        [ -n "$label" ] || continue
        report "$label (staged)" "$(scan_staged "$regex")"
    done <<EOF
$(patterns)
EOF
fi

# 3. file names that alone say "do not publish"; credential files are covered by
# the value patterns above, so they are not listed here.
badnames=$(git ls-files --cached --others --exclude-standard \
    | grep -E '(^|/)\.env$|\.(db|sqlite|sqlite3|mmdb|pcap|key|p12|pfx)$' \
    | skip || true)
report "suspicious file names" "$badnames"

if [ "$found" -ne 0 ]; then
    printf '\nleak-check: remove or redact the hits above, then run again.\n'
    exit 1
fi

printf 'leak-check: clean (%s files scanned)\n' \
    "$(git ls-files --cached --others --exclude-standard | wc -l | tr -d ' ')"
