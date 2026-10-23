#!/bin/sh
# Bring upstream CrowdSec into the fork and prove the result still builds.
#
#   scripts/sync-upstream.sh                  # merge upstream/master
#   scripts/sync-upstream.sh --tag v1.8.3     # merge that release instead
#   scripts/sync-upstream.sh --continue       # conflicts resolved: build, test, report
#   scripts/sync-upstream.sh --push           # push once build, tests and leak-check pass
#
# The merge is a plain "git merge": one commit per upstream update, no rebase, no
# force push, so the branch GitHub shows as "13 commits ahead" stays meaningful.
# Conflicts are expected in the files this fork edits (README, .golangci.yml,
# .github/workflows, a few lint touch-ups); the new packages are additive.
set -eu

die() {
	printf 'sync-upstream: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat <<'EOF'
usage: scripts/sync-upstream.sh [--tag VERSION] [--continue] [--push]
                                [--set-version VERSION] [--no-build] [--no-test]

  --tag VERSION      merge this upstream tag (e.g. v1.8.3) instead of upstream/master
  --continue         the merge is resolved; run build, tests and leak-check
  --push             push to origin/master after everything passed
  --set-version V    bump the default CROWDSEC_VERSION in deploy/docker to V
                     (also picks the image tag; commit the change separately)
  --no-build         skip "make build"
  --no-test          skip the tests of the new packages
EOF
}

tag=
cont=0
push=0
newversion=
do_build=1
do_test=1

while [ $# -gt 0 ]; do
	case "$1" in
		--tag) tag=${2:?--tag needs a version, e.g. v1.8.3}; shift 2 ;;
		--set-version) newversion=${2:?--set-version needs a version, e.g. v1.8.3}; shift 2 ;;
		--continue) cont=1; shift ;;
		--push) push=1; shift ;;
		--no-build) do_build=0; shift ;;
		--no-test) do_test=0; shift ;;
		-h|--help) usage; exit 0 ;;
		*) printf 'sync-upstream: unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
	esac
done

if [ -n "$newversion" ] && [ "$push" -eq 1 ]; then
	die "--set-version edits files; commit them and push separately"
fi

cd "$(git rev-parse --show-toplevel)"

git remote get-url upstream >/dev/null 2>&1 ||
	die "no 'upstream' remote; add it with: git remote add upstream https://github.com/crowdsecurity/crowdsec.git"

if [ -d "$(git rev-parse --git-path rebase-merge)" ] || [ -d "$(git rev-parse --git-path rebase-apply)" ]; then
	die "a rebase is in progress; finish or abort it first"
fi

branch=$(git symbolic-ref --short HEAD 2>/dev/null || true)
if [ "$branch" != "master" ]; then
	die "on branch '${branch:-detached HEAD}', expected master"
fi

in_merge=0
if git rev-parse --verify --quiet MERGE_HEAD >/dev/null; then
	in_merge=1
	[ "$cont" -eq 1 ] || die "a merge is already in progress; resolve it, then rerun with --continue"
fi

if [ "$in_merge" -eq 0 ] && [ -n "$(git status --porcelain)" ]; then
	die "working tree is not clean; commit or stash first:
$(git status --short)"
fi

printf 'fetching upstream ...\n'
git fetch --tags --prune upstream

if [ -n "$tag" ]; then
	target=$(git rev-parse --verify --quiet "refs/tags/$tag^{commit}") ||
		die "tag $tag does not exist upstream (git fetch --tags upstream)"
	label=$tag
else
	target=$(git rev-parse --verify --quiet "refs/remotes/upstream/master^{commit}") ||
		die "upstream/master is missing after fetch"
	label=upstream/master
fi

if [ "$in_merge" -eq 0 ]; then
	behind=$(git rev-list --count "HEAD..$target")
	if [ "$behind" -eq 0 ] && [ -z "$newversion" ]; then
		printf 'nothing to do: master already contains %s (%s)\n' "$label" "$(git rev-parse --short HEAD)"
		exit 0
	fi

	if [ "$behind" -gt 0 ]; then
		printf 'merging %s (%s), %s new commit(s):\n' "$label" "$(git rev-parse --short "$target")" "$behind"
		git log --oneline --no-decorate "HEAD..$target" | head -n 10
		[ "$behind" -le 10 ] || printf '  ... and %s more\n' "$((behind - 10))"

		if ! git merge --no-edit -m "Merge upstream ${tag:-master}" "$target"; then
			printf '\nconflicts in:\n' >&2
			git diff --name-only --diff-filter=U | sed 's/^/  /' >&2
			cat >&2 <<'EOF'

Resolve them, then:
  git add <files>
  scripts/sync-upstream.sh --continue
Abort with: git merge --abort
EOF
			exit 1
		fi
	else
		printf 'nothing to merge: master already contains %s\n' "$label"
	fi
else
	unresolved=$(git diff --name-only --diff-filter=U)
	[ -z "$unresolved" ] || die "still unmerged: $unresolved"
	git commit --no-edit >/dev/null
	printf 'merge committed: %s\n' "$(git log --oneline -1)"
fi

if [ -n "$newversion" ]; then
	case "$newversion" in
		v[0-9]*) ;;
		*) die "--set-version expects a version like v1.8.3" ;;
	esac
	printf 'setting CROWDSEC_VERSION=%s in deploy/docker\n' "$newversion"
	for f in deploy/docker/.env.example deploy/docker/docker-compose.yml; do
		sed -e "s|^CROWDSEC_VERSION=.*|CROWDSEC_VERSION=$newversion|" \
			-e "/CROWDSEC_VERSION/ s|:-v[0-9][0-9.]*}|:-$newversion}|g" \
			"$f" >"$f.tmp"
		mv "$f.tmp" "$f"
	done
	git diff --stat -- deploy/docker/.env.example deploy/docker/docker-compose.yml
	printf 'commit this separately, e.g.: git commit -m "docker: default to %s"\n' "$newversion"
fi

if [ "$do_build" -eq 1 ]; then
	make_bin=
	for candidate in make gmake; do
		command -v "$candidate" >/dev/null 2>&1 || continue
		vmajor=$("$candidate" --version 2>/dev/null | sed -n 's/^GNU Make \([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1/p' | head -n 1)
		vminor=$("$candidate" --version 2>/dev/null | sed -n 's/^GNU Make \([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\2/p' | head -n 1)
		[ -n "$vmajor" ] || continue
		if [ "$vmajor" -gt 4 ] || { [ "$vmajor" -eq 4 ] && [ "$vminor" -ge 1 ]; }; then
			make_bin=$candidate
			break
		fi
	done
	[ -n "$make_bin" ] || die "GNU make >= 4.1 not found (macOS: brew install make, then use gmake)"

	buildlog=$(mktemp "${TMPDIR:-/tmp}/sync-upstream.XXXXXX")
	trap 'rm -f "$buildlog"' EXIT INT TERM
	printf 'building with %s ...\n' "$make_bin"
	if ! "$make_bin" build >"$buildlog" 2>&1; then
		tail -n 30 "$buildlog" >&2
		if grep -q 'libre2-dev is not installed' "$buildlog"; then
			printf 'hint: brew install re2 pkgconf, or run: %s BUILD_RE2_WASM=1 build\n' "$make_bin" >&2
		fi
		die "build failed"
	fi
	rm -f "$buildlog"
	trap - EXIT INT TERM
	printf 'build ok\n'
fi

if [ "$do_test" -eq 1 ]; then
	printf 'testing the fork packages ...\n'
	go test ./pkg/webui/... ./pkg/blocklistserver/... ./cmd/cswebui/... ./cmd/csblocklistd/...
fi

printf 'leak-check ...\n'
scripts/leak-check.sh

sha=$(git rev-parse HEAD)
version=$(sed -n 's/^CROWDSEC_VERSION=//p' deploy/docker/.env.example | head -n 1)

if [ "$push" -eq 1 ]; then
	git push origin "HEAD:master"
	printf '\npushed %s.\n' "$sha"
else
	printf '\nnot pushed yet: scripts/sync-upstream.sh --push\n'
fi

cat <<EOF

deployment host (per deploy/docker/README.md, "Updating a deployment"):

  curl -fsSL https://raw.githubusercontent.com/osxdoc/crowdsec_free/master/deploy/docker/build-image.sh \\
    | sh -s -- $sha ${version:-v1.8.3}
  docker compose up -d
EOF
