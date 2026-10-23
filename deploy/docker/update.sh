#!/bin/sh
# Build the current fork commit on this host and restart the stack with it.
#
#   cd ~/crowdsec && ./update.sh                 # latest master
#   ./update.sh --ref 1a2b3c4                    # a specific commit or tag
#   ./update.sh --version v1.8.3                 # override CROWDSEC_VERSION
#   ./update.sh --dry-run                        # show the steps, change nothing
#   ./update.sh --no-backup
#
# The image is built while the old containers keep running. Only the backup and
# the restart stop them, for a few seconds. Images are tagged
# crowdsec-free:<version>-<commit>, so an already built commit is not rebuilt,
# and a UI that does not come back up rolls the previous image back.
set -eu

repo=${REPO:-osxdoc/crowdsec_free}
dir=${PWD}
ref=
version=
dry=0
backup=1

die() { printf 'update: %s\n' "$*" >&2; exit 1; }
say() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }

usage() {
	cat <<'EOF'
usage: ./update.sh [--ref REF] [--version X] [--dir PATH] [--no-backup] [--dry-run]

  --ref REF        commit, tag or branch to build (default: latest master)
  --version X      image tag and compiled version (default: CROWDSEC_VERSION in .env)
  --dir PATH       deployment directory (default: current directory)
  --no-backup      skip the config/data archive
  --dry-run        print what would run, without building or restarting
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
		--ref) ref=${2:?--ref needs a commit, tag or branch}; shift 2 ;;
		--version) version=${2:?--version needs a value, e.g. v1.8.2}; shift 2 ;;
		--dir) dir=${2:?--dir needs a path}; shift 2 ;;
		--no-backup) backup=0; shift ;;
		--dry-run) dry=1; shift ;;
		-h|--help) usage; exit 0 ;;
		*) printf 'update: unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
	esac
done

cd "$dir"
compose_file=
for candidate in docker-compose.yml docker-compose.yaml; do
	if [ -f "$candidate" ]; then compose_file=$candidate; break; fi
done
[ -n "$compose_file" ] || die "no docker-compose.yml/.yaml in $dir"
[ -f .env ] || die "no .env in $dir (it holds CROWDSEC_VERSION)"

if [ -z "$version" ]; then
	version=$(sed -n 's/^CROWDSEC_VERSION=//p' .env | head -n 1)
fi
[ -n "$version" ] || die "CROWDSEC_VERSION is empty and --version was not given"

docker compose version >/dev/null 2>&1 || die "'docker compose' is not available"

if [ -z "$ref" ]; then
	if command -v git >/dev/null 2>&1; then
		ref=$(git ls-remote "https://github.com/$repo.git" refs/heads/master | cut -f1)
	else
		ref=$(curl -fsS "https://api.github.com/repos/$repo/commits/master" |
			sed -n 's/.*"sha": "\([0-9a-f]\{40\}\)".*/\1/p' | head -n 1)
	fi
	[ -n "$ref" ] || die "could not resolve the latest commit of $repo"
fi

sha=$ref
if command -v git >/dev/null 2>&1; then
	resolved=$(git ls-remote "https://github.com/$repo.git" "$ref" 2>/dev/null | cut -f1 | head -n 1) || true
	[ -n "$resolved" ] && sha=$resolved
fi
case "$sha" in
	[0-9a-f][0-9a-f][0-9a-f]*) short=$(printf '%s' "$sha" | cut -c1-7) ;;
	*) short=$(printf '%s' "$sha" | sed 's/[^[:alnum:]._-]/-/g') ;;
esac

image="crowdsec-free:$version"
built="$image-$short"
previous="$image-prev"

say "deployment $dir, version $version, commit $short"

if docker image inspect "$built" >/dev/null 2>&1; then
	say "image $built already built, skipping the build"
else
	build_url="https://raw.githubusercontent.com/$repo/$ref/deploy/docker/build-image.sh"
	say "building $built (the running stack keeps serving)"
	if [ "$dry" -eq 1 ]; then
		say "would fetch $build_url and build with IMAGE=$built"
	else
		script=$(mktemp)
		trap 'rm -f "$script"' EXIT INT TERM
		curl -fsSL -o "$script" "$build_url" || die "could not fetch $build_url"
		IMAGE="$built" sh "$script" "$ref" "$version"
		rm -f "$script"
		trap - EXIT INT TERM
	fi
fi

if [ "$backup" -eq 1 ]; then
	archive="backup-$(date +%F)-$short.tgz"
	if [ -f "$archive" ]; then
		say "backup $archive already exists"
	else
		say "stopping the services for a consistent $archive"
		if [ "$dry" -eq 1 ]; then
			say "would run: docker compose stop crowdsec csblocklistd && tar czf $archive config data"
		else
			docker compose stop crowdsec csblocklistd
			tar czf "$archive" config data
		fi
	fi
fi

if docker image inspect "$image" >/dev/null 2>&1; then
	say "keeping the current image as $previous"
	[ "$dry" -eq 1 ] || docker tag "$image" "$previous"
fi

say "pointing $image at $built"
[ "$dry" -eq 1 ] || docker tag "$built" "$image"

if [ "$dry" -eq 1 ]; then
	say "would run: docker compose up -d, then curl 127.0.0.1:<WEBUI_PORT> until it answers"
	say "dry run, nothing was changed"
	exit 0
fi

say "starting the stack"
docker compose up -d

# The login page answering is the quickest end-to-end check: no auth, no proxy,
# and it fails while the container is still starting.
port=$(sed -n 's/^WEBUI_PORT=//p' .env | head -n 1)
port=${port:-8081}
say "waiting for the web UI on 127.0.0.1:$port"
tries=0
until curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:$port/"; do
	tries=$((tries + 1))
	if [ "$tries" -ge 45 ]; then
		printf 'update: web UI did not answer within 90s, rolling back\n' >&2
		docker tag "$previous" "$image"
		docker compose up -d
		exit 1
	fi
	sleep 2
done

say "services: $(docker compose ps --format '{{.Service}}={{.State}}' 2>/dev/null | tr '\n' ' ')"
say "deployed $sha"
printf '\nrollback: docker tag %s %s && docker compose up -d\n' "$previous" "$image"
