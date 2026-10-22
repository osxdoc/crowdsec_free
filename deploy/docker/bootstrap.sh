#!/bin/sh
# Prepares a fresh deployment: fills /etc/crowdsec with the default
# configuration, registers the agent and UI machines directly in the LAPI
# database, registers against the blocklist server, and optionally installs
# hub collections (with GeoIP data).
set -eu

MODE="${1:-all}"

CONFIG_DIR="${CONFIG_DIR:-/etc/crowdsec}"
CONFIG_FILE="${CONFIG_FILE:-$CONFIG_DIR/config.yaml}"
DATA_DIR="${DATA_DIR:-/var/lib/crowdsec/data}"
BLOCKLIST_URL="${BLOCKLIST_URL:-http://csblocklistd:8082/}"
AGENT_LAPI_URL="${AGENT_LAPI_URL:-http://127.0.0.1:8080/}"
UI_LAPI_URL="${UI_LAPI_URL:-http://crowdsec:8080/}"
HUB_COLLECTIONS="${HUB_COLLECTIONS:-crowdsecurity/linux}"
WEBUI_ADMIN_PASSWORD="${WEBUI_ADMIN_PASSWORD:-}"
BLOCKLIST_ADMIN_TOKEN="${BLOCKLIST_ADMIN_TOKEN:-}"
SKIP_HUB_UPDATE="${SKIP_HUB_UPDATE:-false}"

log() {
    printf '[bootstrap] %s\n' "$*"
}

# Portable in-place sed: busybox, GNU and BSD sed all accept -i.bak.
replace_in_file() {
    file="$1"
    placeholder="$2"
    value="$3"

    sed -i.bak "s|$placeholder|$value|g" "$file" && rm -f "$file.bak"
}

mkdir -p "$CONFIG_DIR" "$DATA_DIR"

# --- default configuration and secrets -----------------------------------

configure() {
    if [ -d /etc/crowdsec-defaults ]; then
        # busybox "cp -an src/." copies nothing at all (silently, exit 0), and the
        # runtime image has no GNU coreutils - seed the entries one by one.
        for entry in /etc/crowdsec-defaults/*; do
            name="${entry#/etc/crowdsec-defaults/}"

            if [ -e "$CONFIG_DIR/$name" ]; then
                continue
            fi

            cp -a "$entry" "$CONFIG_DIR/$name"
            log "seeded $name"
        done
    fi

    # The web UI refuses to start with the placeholder hash: generate one.
    if grep -q 'REPLACE_ME_WITH_A_REAL_BCRYPT_HASH' "$CONFIG_DIR/webui.yaml" 2>/dev/null; then
        password="$WEBUI_ADMIN_PASSWORD"

        if [ -z "$password" ]; then
            password="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-16)"
            log "generated web UI password for user 'admin': $password"
        fi

        hash="$(cswebui -hash-password -password "$password")"
        replace_in_file "$CONFIG_DIR/webui.yaml" 'REPLACE_ME_WITH_A_REAL_BCRYPT_HASH' "$hash"
        log "web UI admin password hash written to webui.yaml"
    fi

    # Must happen before csblocklistd starts: it reads the token only once.
    if grep -q 'CHANGE_ME_ADMIN_TOKEN' "$CONFIG_DIR/blocklist.yaml" 2>/dev/null; then
        token="$BLOCKLIST_ADMIN_TOKEN"

        if [ -z "$token" ]; then
            token="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-32)"
            log "generated blocklist admin token: $token"
        fi

        replace_in_file "$CONFIG_DIR/blocklist.yaml" 'CHANGE_ME_ADMIN_TOKEN' "$token"
        replace_in_file "$CONFIG_DIR/webui.yaml" 'CHANGE_ME_ADMIN_TOKEN' "$token"
        log "blocklist admin token written to blocklist.yaml and webui.yaml"
    fi
}

# `cscli machines add` writes to the database directly, so this works before
# the engine is up. Machines created this way are validated.
create_machine() {
    name="$1"
    file="$2"
    url="$3"

    if [ -s "$file" ] && grep -q '^login:' "$file" && grep -q '^password:' "$file"; then
        log "machine '$name' already registered"
        return 0
    fi

    log "registering machine '$name'"
    cscli -c "$CONFIG_FILE" machines add "$name" --auto --force -f "$file" -u "$url"
}

register_machines() {
    create_machine crowdsec-agent "$CONFIG_DIR/local_api_credentials.yaml" "$AGENT_LAPI_URL"
    create_machine cswebui "$CONFIG_DIR/cswebui_credentials.yaml" "$UI_LAPI_URL"
}

# --- central API (self-hosted blocklist server) ---------------------------

register_capi() {
    online_creds="$CONFIG_DIR/online_api_credentials.yaml"

    if [ -s "$online_creds" ] && grep -q '^login:' "$online_creds"; then
        log "already registered against a blocklist server"
        return 0
    fi

    log "waiting for blocklist server $BLOCKLIST_URL"
    waited=0

    while ! curl -fsS "${BLOCKLIST_URL%/}/health" >/dev/null 2>&1; do
        waited=$((waited + 2))
        if [ "$waited" -ge "${BLOCKLIST_TIMEOUT:-120}" ]; then
            log "blocklist server not reachable, skipping registration"
            return 0
        fi

        sleep 2
    done

    log "registering against blocklist server $BLOCKLIST_URL"
    cscli -c "$CONFIG_FILE" capi register --url "$BLOCKLIST_URL" -f "$online_creds"
}

# --- hub collections ------------------------------------------------------

install_hub() {
    if [ "$SKIP_HUB_UPDATE" != "true" ]; then
        if cscli -c "$CONFIG_FILE" hub update --with-content; then
            log "hub index and data files updated"
        else
            log "hub update failed (offline?), keeping the existing hub"
        fi
    fi

    for collection in $HUB_COLLECTIONS; do
        [ -n "$collection" ] || continue

        if cscli -c "$CONFIG_FILE" collections install "$collection"; then
            log "collection $collection installed"
        else
            log "could not install collection $collection"
        fi
    done
}

case "$MODE" in
    config)
        configure
        register_machines
        install_hub
        ;;
    register)
        register_capi
        ;;
    all)
        configure
        register_machines
        install_hub
        register_capi
        ;;
    *)
        log "unknown mode '$MODE' (expected config, register or all)"
        exit 1
        ;;
esac
