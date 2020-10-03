#!/usr/bin/env bash
set -euo pipefail

OS="$(tr '[A-Z]' '[a-z]' <<< "$(uname -s)")"
WORKDIR="$(git rev-parse --show-toplevel)"

: "${VAULTSIGN:=${WORKDIR}/target/release/vaultsign}"
: "${VAULT_LOG:=error}"
: "${VAULT_ADDR:=http://127.0.0.1:8200}"
: "${VAULT_GPG_PLUGIN_VER:=v0.2.4}"
: "${VAULT_GPG_PLUGIN_URL:=https://github.com/LeSuisse/vault-gpg-plugin}"
: "${INTEGRATION_DIR:=$(mktemp -d)}"
: "${SILENT:=true}"
 
export VAULT_ADDR

# Commandeer output streams for a test that's easier on the eyes.
exec 3>&1
exec 4>&2
if [ "${SILENT}" = "true" ]; then
    exec 1>/dev/null
    exec 2>/dev/null      
else
    VAULT_LOG=debug
    export GIT_TRACE=1
    set -x
fi

test_teardown() {
    [ $? -ne 0 ] && echo >&4 "fail"

    printf >&4 "%-42s %s" "> acceptance test teardown:" ""
    rm -rf "${INTEGRATION_DIR}"
    killall -9 vault
    sleep 1
    echo >&4 "ok"
}
trap test_teardown SIGINT SIGTERM EXIT

test_setup() {
    printf >&4 "%-42s %s" "> acceptance test setup:" ""
    
    mkdir -p "${WORKDIR}/tmp/${OS}_amd64"
    if ! test -f "${WORKDIR}/tmp/${OS}_amd64/vault-gpg-plugin"; then
        curl -sfLO \
            ${VAULT_GPG_PLUGIN_URL}/releases/download/${VAULT_GPG_PLUGIN_VER}/${OS}_amd64.zip 
        unzip "${OS}_amd64.zip" -d "${WORKDIR}/tmp/${OS}_amd64"
        rm -f "${OS}_amd64.zip" "${WORKDIR}/tmp/${OS}_amd64/*.sha256sum"
    fi

    vault server \
        -dev \
        -dev-root-token-id=root \
        -dev-plugin-dir="${WORKDIR}/tmp/${OS}_amd64" \
        -log-level=${VAULT_LOG} &
    sleep 3

    [ "${VAULT_LOG}" = "debug" ] && \
        vault audit enable file file_path=/dev/stderr
 
    vault secrets enable transit
    vault write -f transit/keys/test type="rsa-4096"

    vault secrets enable -path=gpg -plugin-name=vault-gpg-plugin plugin
    vault write -f gpg/keys/test key_bits=4096 email="martin@baillie.email" real_name="Martin Baillie"

    cd "${INTEGRATION_DIR}"
    git init

    git config --local user.email "martin@baillie.email"
    git config --local user.name "Martin Baillie"
    # git config --local gpg.x509.program "${VAULTSIGN}"
    git config --local gpg.program "${VAULTSIGN}"
    echo >&4 "ok"
}

test_acceptance() {
    export VAULT_SIGN_PATH=transit/sign/test/sha2-256
    printf >&4 "%-42s %s" "> signed commit (vault transit backend):" ""
    touch test-transit
    git add test-transit
    git commit -m test-transit -S
    echo >&4 "ok"
    printf >&4 "%-42s %s" "> signed tag (vault transit backend):" ""
    git tag -m test-transit -s test-transit
    echo >&4 "ok"

    export VAULT_VERIFY_PATH=transit/verify/test
    printf >&4 "%-42s %s" "> verified commit (vault transit backend):" ""
    git verify-commit HEAD
    echo >&4 "ok"
    printf >&4 "%-42s %s" "> verified log (vault transit backend):" ""
    git log -1 --show-signature
    echo >&4 "ok"
    printf >&4 "%-42s %s" "> verified tag (vault transit backend):" ""
    git verify-tag test-transit
    echo >&4 "ok"

    export VAULT_SIGN_PATH=gpg/sign/test/sha2-256
    printf >&4 "%-42s %s" "> signed commit (vault gpg plugin):" ""
    touch test-gpg
    git add test-gpg
    git commit -m test-gpg -S
    echo >&4 "ok"
    printf >&4 "%-42s %s" "> signed tag (vault gpg plugin):"
    git tag -m test-gpg -s test-gpg
    echo >&4 "ok"

    export VAULT_VERIFY_PATH=gpg/verify/test
    printf >&4 "%-42s %s" "> verified commit (vault gpg plugin):" ""
    git verify-commit HEAD
    echo >&4 "ok"
    printf >&4 "%-42s %s" "> verified log (vault gpg plugin):" ""
    git log -1 --show-signature
    echo >&4 "ok"
    printf >&4 "%-42s %s" "> verified tag (vault gpg plugin):" ""
    git verify-tag test-gpg
    echo >&4 "ok"
}

test_setup
test_acceptance
