#!/bin/sh
# Build the image on the machine that will run it, from a commit that has already
# been pushed. No source tree is kept on the deployment host: GitHub serves the
# tarball and the build happens in a temporary directory that is removed again.
#
#   ./deploy/docker/build-image.sh <ref> [version]
#   ./deploy/docker/build-image.sh 1a2b3c4 v1.8.2
#
# On a host with nothing checked out, the script does not need the repository:
#
#   curl -fsSL https://raw.githubusercontent.com/<owner>/crowdsec_free/master/deploy/docker/build-image.sh \
#     | sh -s -- <ref> v1.8.2
#
# <version> is the version string compiled into the binaries (VERSION build arg)
# and the image tag, so it must match CROWDSEC_VERSION in .env.
set -eu

ref="${1:?usage: build-image.sh <ref> [version]}"
version="${2:-$ref}"
repo="${REPO:-osxdoc/crowdsec_free}"
image="${IMAGE:-crowdsec-free:${version}}"

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

log "fetching $repo@$ref"
url="https://codeload.github.com/$repo/tar.gz/$ref"
if ! curl -fsSL -o "$tmp/src.tgz" "$url"; then
    # bare branch names are only reachable under refs/heads
    curl -fsSL -o "$tmp/src.tgz" "https://codeload.github.com/$repo/tar.gz/refs/heads/$ref"
fi
tar xzf "$tmp/src.tgz" -C "$tmp" --strip-components=1
[ -f "$tmp/deploy/docker/Dockerfile" ] || {
    exit 1
}

log "building $image from $repo@$ref"
docker build -f "$tmp/deploy/docker/Dockerfile" --build-arg "VERSION=$version" -t "$image" "$tmp"
log "built $(docker image inspect --format '{{.Id}}' "$image") ($(docker image inspect --format '{{.Size}}' "$image") bytes)"
