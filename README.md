# git-agecrypt (with x- fixes)

Git integration usable to store encrypted secrets in the git repository while having the plaintext available in the working tree. An alternative to [git-crypt](https://github.com/AGWA/git-crypt) using [age](https://age-encryption.org) instead of GPG.

Do not use this tool unless you understand the security implications. I am by no mean a security expert and this code hasn't been audited. Use at your own risk.

## x- enahancements

### Commands to use
See `package.json` for useful commands. 

### macOS install notes

If compiling fails with port's `libiconv` incompatibility error:

```console
$ RUSTFLAGS="-L /usr/lib -l iconv" cargo build --release
```

Or on other systems, ensure the `port` library headers are available for compilation.

### New features 

#### Aliases

Instead of using long cryptographic keys directly in `git-agecrypt.toml`, you can define human-readable aliases in the `[aliases]` section and reference them in your `[config]` entries.

```toml
[aliases]
bob = 'age1xgrjk6eyckfkj85zac7jzhwusagj0vh77y64pk0tpczs5qgjmvdswgmjyq'
alice = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...'

[config]
"secrets/**" = ['bob', 'alice']
"protected/*.md" = ['bob']
```

Aliases are resolved transparently before encryption. Both aliases and direct keys (Age keys, ed25519 SSH keys, Age plugin stubs) can be mixed in the same recipient array. If a recipient string doesn't match any alias, it's passed through as-is.

#### Folder and Glob Patterns

The `[config]` section supports folder prefixes and glob patterns, not just exact file paths. This allows mapping recipients to multiple files with a single entry.

**Matching order:**
1. Exact path match (checked first)
2. Directory prefix (e.g., `"protected"` matches `protected/secret.md`)
3. Glob pattern (e.g., `"**/*.md"` matches any `.md` file recursively)

**Examples:**

```toml
[config]
"secrets/api-key.txt" = ['bob']       # exact file
"protected" = ['alice']               # all files under protected/
"protected/*.md" = ['bob', 'alice']   # .md files in protected/ (not recursive)
"**/*.env" = ['bob']                  # all .env files recursively
```

**Note:** When adding paths via CLI, the path must exist or be a valid glob pattern:

```console
$ git-agecrypt config add -r "age1..." -p "secrets/**"
```

#### Encrypted Identity Files (AGE_PASSPHRASE)

git-agecrypt supports passphrase-protected (encrypted) identity files for decryption operations. This enables secure storage of private keys while allowing automated usage in CI/CD pipelines and scripts.

**Usage:**

```console
$ AGE_PASSPHRASE='your-passphrase' git pull
$ AGE_PASSPHRASE='your-passphrase' git-agecrypt status
$ AGE_PASSPHRASE='your-passphrase' bun run status
$ AGE_PASSPHRASE='your-passphrase' smerge
$ AGE_PASSPHRASE='your-passphrase' windsurf-next
```

**Behavior:**

| Identity type | AGE_PASSPHRASE set | Result |
|---------------|-------------------|--------|
| Plaintext | N/A | Parsed and used directly |
| Encrypted | Yes | Decrypted with passphrase, then used |
| Encrypted | No | Encryption works, decryption fails with clear error |

**Status command:**

When running `git-agecrypt status`, encrypted identities show their validation state:
- With `AGE_PASSPHRASE`: fully validated (decryption tested)
- Without `AGE_PASSPHRASE`: format validated only, with note: *"encrypted, AGE_PASSPHRASE not detected, decryption was not tested"*

**Creating encrypted identity files:**

```console
$ age-keygen | age -p -a > ~/bob.identity
```

Then configure it:

```console
$ git-agecrypt config add -i ~/bob.identity
```

#### Passphrase Getter (-g)

Instead of setting `AGE_PASSPHRASE` manually in your environment, you can configure git-agecrypt to obtain the passphrase from an external command. This keeps the passphrase ephemeral and avoids exposing it in shell history or environment listings.

**Configuration:**

Add a `[passphrase]` section to `git-agecrypt.toml`:

```toml
[passphrase]
sops = "sops -d --extract '[\"age_passphrase\"]' secrets.enc.yaml"
linux = "secret-tool lookup application age identity-file ./bobs.identity"
macos = "security find-generic-password -a age -s identity-passphrase -w"
```

**Usage:**

```console
# Explicit: use a specific getter key
$ git-agecrypt -g linux status
$ git-agecrypt -g macos config list -r

# Implicit: if 'sops' key exists, it's used automatically
$ git-agecrypt status
```

**Triggers (priority order):**

1. **`-g <key>` argument** (highest priority): Uses the specified key from `[passphrase]` section
2. **`AGE_PASSPHRASE_GETTER` env var**: 
   - If set to a non-empty value: uses that value as the getter key
   - If set to empty string: suppresses the implicit `sops` check (useful to disable auto-getter)
3. **Implicit `sops`** (lowest priority): If no `-g` argument and no env var, but `sops` key exists in config, uses it automatically

**Using AGE_PASSPHRASE_GETTER env var:**

This is useful when git-agecrypt is invoked by other tools (IDE, git hooks) where you can't pass `-g`:

```console
# Use 'linux' getter for all git-agecrypt invocations in this session
$ export AGE_PASSPHRASE_GETTER=linux
$ windsurf-next      # IDE will use linux getter when git-agecrypt runs
$ git pull           # git hooks will use linux getter

# Suppress automatic sops getter (empty value)
$ AGE_PASSPHRASE_GETTER= git pull
```

**How -g feature works:**

- The command is executed via `sh -c` (supports pipes and complex shell commands)
- Output is trimmed and set as `AGE_PASSPHRASE` for the duration of git-agecrypt's execution
- Clear error messages if command fails or returns empty output

**Example with secret-tool (Linux):**

```console
# Store passphrase in GNOME Keyring
$ secret-tool store --label="Age Identity" application age identity-file ./bobs.identity

# Configure getter
$ cat git-agecrypt.toml
[passphrase]
linux = "secret-tool lookup application age identity-file ./bobs.identity"

# Use it
$ git-agecrypt -g linux status
```

## Current CLI structure

git-agecrypt init
git-agecrypt status
git-agecrypt config add -r ... -p ...
git-agecrypt config remove -r ... -p ...
git-agecrypt config list -i/-r
git-agecrypt deinit
(hidden) clean, smudge, textconv for git filters

## Why should I use this?

Short answer: you probably shouldn't. Before considering this approach, take a look at [SOPS](https://github.com/mozilla/sops) and [Hashicorp Vault](https://www.vaultproject.io/) if they are better suited for the problem at hand. **They have a clear security advantage** over `git-agecrypt`.

The one use-case where it makes sense to use `git-agecrypt` instead is when you want to keep some files secret on a (potentially public) git remote, but you need to have the plaintext in the local working tree because you cannot hook into the above tools for your workflow. **Being lazy is not an excuse to use this software.**

I have written this to have a more portable and easy to set up alternative to `git-crypt`.

## Usage

1. First setup `git-agecrypt` integration for a repository:

    ```console
    $ git-agecrypt init
    ```

    This command configures the necessary hooks to encrypt and decrypt git objects and to generate clear-text output for `git diff`, `log` etc.

2. Next step is to configure rules to map encryption keys to file paths:

    ```console
    $ git-agecrypt config add -r "$(cat ~/.ssh/id_ed25519.pub)" -p path/to/secret.1 path/to/secret.2
    ```

    An arbitrary number of recipients (public keys) and files can be specified using a single command. Keys can be Age keys, ed25519 SSH keys or stubs generated by Age plugins, e.g. for keys stored on Yubikey PIV module. It is enough to have only one secret key to decrypt the files later.

    Configuration is saved to `git-agecrypt.toml` file inside the root of the repository

3. After that, edit `.gitattributes` to actually use these filters. This is currently a manual step.

    ```gitattributes
    path/to/secret.1 filter=git-agecrypt diff=git-agecrypt
    path/to/secret.2 filter=git-agecrypt diff=git-agecrypt
    ```

    Files can be specified in the same way as for `.gitignore` but keep in mind that filters are only applied for files, not directories, so that you need to write `/secrets/**` instead of `/secrets/` to encrypt each file under the `secrets` directory.

4. Finally, configure the locations of age identities (private keys) which can be used to decrypt files

    ```console
    $ git-agecrypt config add -i ~/.ssh/id_ed25520
    ```

    Location of secret keys are stored outside of version control in `.git/config` to support having them in different location for each checkout.

## Behind the scenes

This application hooks into git using [`smudge` `clean` and `textconv` filters](https://git-scm.com/book/en/v2/Customizing-Git-Git-Attributes). Issuing `git-agecrypt init` adds them to the repository local `.git/config`:

```gitconfig
[filter "git-agecrypt"]
        required = true
        smudge = /path/to/git-agecrypt smudge -f %f
        clean = /path/to/git-agecrypt clean -f %f
[diff "git-agecrypt"]
        textconv = /path/to/git-agecrypt textconv
```

These filters are assigned to repository files in `.gitattributes`. When configured, they are being called for each file when touching the index. Encryption is non-deterministic, so each time `git status`, `git add`, etc is run a new ciphertext would be generated. To circumvent this, a [blake3](https://github.com/BLAKE3-team/BLAKE3) hash is calculated for the plaintext and stored under `.git/git-agecrypt/` directory. While the hashes stored match with the file contents in the working tree, `git-agencrypt` loads the previous ciphertext from the index when git asks for it.

Encryption can work without access to private keys (what Age calls identities). In order to pull remote changes of encrypted files or to see plain diff of files, these have to be configured with `git-agecrypt config`. They are stored in `.git/config` conforming to standard git config format:

```gitconfig
[git-agecrypt "config"]
        identity = /home/vlaci/.ssh/id_ed25519
        identity = ...
```

## Limitations

The following limitations can be easily improved upon, but they are not blockers for my use-case.

- The application is started once for each file for every git operation. It can cause slowdown when the repository contains many encrypted files. A possible mitigation for this issue could be the implementation of the [long-running process protocol](https://github.com/git/git/blob/master/Documentation/technical/long-running-process-protocol.txt) but it is usable as it is for a couple of small files.

- During encryption/decryption the whole file is loaded into memory. This can cause issues when encrypting large files.
