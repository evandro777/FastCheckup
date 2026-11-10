#!/usr/bin/env bash
# One-off: make the key that signs the Flatpak remote (see docs/FLATPAK-SIGNING.md for what each half does).
#   flatpak/new-signing-key.sh [path-for-the-private-key]
# Writes the PUBLIC half to flatpak/signing-key.b64 (commit it) and the PRIVATE half to a file outside the repository,
# which you then store as the GitHub secret FLATPAK_GPG_PRIVATE_KEY. Your own GPG keyring is not touched.
set -euo pipefail
umask 077
cd "$(dirname "$0")"
public=signing-key.b64
private=${1:-$HOME/.local/share/fastcheckup-flatpak-private-signing.asc}

# A new key breaks every user's existing remote (they trust the old one), so never replace it by accident.
[ ! -e "$public" ] || { echo "$public already exists: refusing to make a new key (see 'Replacing the key' in docs/FLATPAK-SIGNING.md)" >&2; exit 1; }
[ ! -e "$private" ] || { echo "$private already exists: choose another path" >&2; exit 1; }
# The private key must never end up in the repository or in a synced folder.
case "$(realpath -m "$private")" in
  "$(realpath ..)"/* | */Dropbox/*) echo "put the private key outside the repository and Dropbox, e.g. ~/.local/share/" >&2; exit 1 ;;
esac
mkdir -p "$(dirname "$private")"

export GNUPGHOME
GNUPGHOME=$(mktemp -d)
# The temporary gpg-agent keeps the directory busy until it is stopped.
trap 'gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT

# No passphrase (CI imports it with --batch) and no expiry (an expired key silently breaks updates).
gpg --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key "FastCheckup Flatpak <noreply@users.noreply.github.com>" ed25519 sign never 2>/dev/null
fpr=$(gpg --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')

gpg --export "$fpr" | base64 -w0 > "$public"
gpg --export-secret-keys --armor "$fpr" > "$private"

# The same check CI uses to find the key: the committed file must give back this fingerprint.
check=$(base64 -d "$public" | gpg --show-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')
[ "$check" = "$fpr" ] || { rm -f "$public" "$private"; echo "fingerprint check failed" >&2; exit 1; }

cat <<EOF
Key $fpr created.

  public  (commit it):   flatpak/$public
  private (keep secret): $private

Next:
  1. Store the private key as the GitHub secret FLATPAK_GPG_PRIVATE_KEY:
       gh secret set FLATPAK_GPG_PRIVATE_KEY < $private
     or on the website: repo Settings -> Secrets and variables -> Actions -> New repository secret,
     paste the whole file (BEGIN to END line).
  2. Keep a private backup of $private (password manager), then delete the loose file:  shred -u $private
  3. The other one-time GitHub settings are in RELEASING.md.
EOF
