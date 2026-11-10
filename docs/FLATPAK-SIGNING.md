# Signing the Flatpak remote

How the signed Flatpak repository is built on GitHub, and what you do once to set it up.

## Why it is signed

`flatpak.yml` publishes an OSTree repository (the "remote") on GitHub Pages. Flatpak refuses to install from an unsigned remote when the install is system-wide (`--system`), and Linux Mint's Update Manager only sees system-wide installs. So the repository is signed with a GPG key.

A key is a **pair** made together:

| Half    | File                                 | Where it lives                     | What it does                                                       |
|---------|--------------------------------------|------------------------------------|--------------------------------------------------------------------|
| Public  | `flatpak/signing-key.b64`            | Committed to the repository        | Lets Flatpak on the user's machine *check* signatures. Not secret. |
| Private | `private-key.asc` (outside the repo) | **Never** committed; GitHub secret | Creates signatures. Whoever has it can sign updates as you.        |

On a version tag, CI imports the private key from the secret `FLATPAK_GPG_PRIVATE_KEY`, signs the repository, and puts the
public key into `fastcheckup.flatpakrepo` so users' Flatpak knows which key to trust.

## One-time setup

You only do this once per project (or again if the key is ever lost or leaked, see "Replacing the key").

### 1. Make the key pair

Use a throwaway key folder so your own GPG keys are not touched.

```bash
flatpak/new-signing-key.sh
```

It makes the pair in a temporary keyring (your own GPG keys are not touched), writes `flatpak/signing-key.b64`, writes the private key to `~/.local/share/fastcheckup-flatpak-private-signing.asc` (or the path you pass as an argument), checks that the two match, deletes the temporary keyring and prints the next steps. It refuses to run if `signing-key.b64` already exists. Commit `flatpak/signing-key.b64`. Never commit the private file.

### 2. Store the private key as a GitHub secret

A *secret* is a value GitHub keeps for the repository: workflows can read it, but nobody can view it afterwards (you can only replace it). The name must be exactly `FLATPAK_GPG_PRIVATE_KEY`, because `flatpak.yml` reads it by that name.

#### With the website

1. Open the repository on GitHub → **Settings** → **Secrets and variables** → **Actions**.
2. Click **New repository secret**.
3. Name: `FLATPAK_GPG_PRIVATE_KEY`.
4. Secret: open `private-key.asc` in a text editor and copy **everything**, from
   `-----BEGIN PGP PRIVATE KEY BLOCK-----` to `-----END PGP PRIVATE KEY BLOCK-----`.
5. Click **Add secret**.

#### With the `gh` command (alternative)

`gh` is GitHub's official command-line tool: it does from the terminal what you would click on the website.

```bash
sudo apt install gh        # once; Debian/Ubuntu/Mint
gh auth login              # once; follow the prompts (browser or token)

# From a clone of the repository (or add --repo evandro777/FastCheckup):
gh secret set FLATPAK_GPG_PRIVATE_KEY < private-key.asc
```

`gh secret set NAME` creates or replaces the secret `NAME`; `< private-key.asc` is the shell feeding the file's contents
in as the value. List the secrets (names only) with `gh secret list`.

### 3. Back it up, then delete the loose file

GitHub never shows the secret again. Keep a copy of `private-key.asc` in a password manager or another private place, then delete the loose copies:

```bash
shred -u private-key.asc            # or rm; the file is only a copy of what is in the keyring
rm -rf "$GNUPGHOME"                 # the temporary keyring also holds the private key
unset GNUPGHOME
```

### 4. The other one-time GitHub settings

These are not about the key, but the first tag fails without them (details in [RELEASING.md](../RELEASING.md)):

- Settings → Pages → Source: **GitHub Actions**.
- Settings → Environments → `github-pages` → add a **tag** deployment rule `v*`.

## What CI does with the key

In `.github/workflows/flatpak.yml`, on a `v*` tag only (secrets are not available to pull requests):

1. `echo "$GPG_PRIVATE_KEY" | gpg --batch --import` loads the private key from the secret.
2. The fingerprint is read from the committed public key (`base64 -d flatpak/signing-key.b64 | gpg --show-keys ...`) and exported as `FLATPAK_GPG_KEY`.
3. `flatpak/build.sh --bundle` passes it to `flatpak-builder --gpg-sign=<fingerprint>`, which signs the commits and the repository summary. The signed repository is then deployed to GitHub Pages.
4. The `pages` job writes `GPGKey=<contents of signing-key.b64>` into `fastcheckup.flatpakrepo`.

Pushes and pull requests build the bundle without a key (with a warning), so CI works before you have made one.

## Checking a build

After the first tag, on any machine with Flatpak:

```bash
flatpak remote-add --system --if-not-exists fastcheckup https://evandro777.github.io/FastCheckup/fastcheckup.flatpakrepo
flatpak install --system fastcheckup io.github.evandro777.FastCheckup
```

An unsigned or wrongly signed repository makes the install fail with a GPG error. To inspect a repository built locally (`flatpak/build.sh --bundle` without a key gives an unsigned one):

```bash
ostree summary --view --repo=flatpak/repo      # a signed repo lists a GPG signature
```

## Replacing the key

If the private key is lost or leaked, make a new pair (steps 1-3), commit the new `signing-key.b64`, and replace the secret. Users who already added the remote still trust the *old* key, so their updates will fail until they remove and re-add the remote:

```bash
flatpak remote-delete --system fastcheckup
flatpak remote-add --system fastcheckup https://evandro777.github.io/FastCheckup/fastcheckup.flatpakrepo
```

This is why the key has no expiry date and the private key needs a backup.

