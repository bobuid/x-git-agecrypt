mod age;
mod cli;
mod config;
mod ctx;
mod git;

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use cli::run;
use config::AppConfig;
use git::Repository;

fn main() -> Result<()> {
    env_logger::init();
    let args = cli::parse_args();
    let repo = git::LibGit2Repository::from_current_dir()?;

    // Handle passphrase getter before running commands
    resolve_passphrase(&args, &repo)?;

    let ctx = ctx::new(repo);
    run(args, ctx)
}

const AGE_PASSPHRASE_GETTER_ENV: &str = "AGE_PASSPHRASE_GETTER";

/// Tracks how the passphrase getter was triggered (for error messages)
#[derive(Clone, Copy)]
enum GetterSource {
    Arg,
    EnvVar,
    ImplicitSops,
}

impl std::fmt::Display for GetterSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetterSource::Arg => write!(f, "-g argument"),
            GetterSource::EnvVar => write!(f, "{} env var", AGE_PASSPHRASE_GETTER_ENV),
            GetterSource::ImplicitSops => write!(f, "implicit sops key in [passphrase] section"),
        }
    }
}

fn resolve_passphrase(args: &cli::Args, repo: &impl Repository) -> Result<()> {
    // Load config to check [passphrase] section
    let cfg = AppConfig::load(&PathBuf::from("git-agecrypt.toml"), repo.workdir())?;

    // Determine which key to use (priority order):
    // 1. Explicit -g <key> argument (highest priority)
    // 2. AGE_PASSPHRASE_GETTER env var:
    //    - if not present: fall through to check sops
    //    - if empty: suppress sops check (return early)
    //    - if non-empty: use its value as getter key
    // 3. Implicit "sops" key if present in config (lowest priority)
    let (getter_key, source): (Option<String>, Option<GetterSource>) = if let Some(ref key) = args.passphrase_getter {
        // -g argument takes highest priority
        (Some(key.clone()), Some(GetterSource::Arg))
    } else {
        // Check AGE_PASSPHRASE_GETTER env var
        match std::env::var(AGE_PASSPHRASE_GETTER_ENV) {
            Ok(env_value) => {
                if env_value.is_empty() {
                    // Empty value = suppress sops, do nothing
                    log::debug!("{} is set but empty, suppressing default sops getter", AGE_PASSPHRASE_GETTER_ENV);
                    return Ok(());
                } else {
                    // Non-empty value = use as getter key
                    log::debug!("Using getter key from {}: {}", AGE_PASSPHRASE_GETTER_ENV, env_value);
                    (Some(env_value), Some(GetterSource::EnvVar))
                }
            }
            Err(_) => {
                // Env var not set, fall through to sops check
                if cfg.has_passphrase_key("sops") {
                    (Some("sops".to_string()), Some(GetterSource::ImplicitSops))
                } else {
                    (None, None)
                }
            }
        }
    };

    let (Some(key), Some(source)) = (getter_key, source) else {
        return Ok(());
    };

    let command = cfg.get_passphrase_command(&key).ok_or_else(|| {
        anyhow::anyhow!(
            "Passphrase getter '{}' not found in [passphrase] section of git-agecrypt.toml (triggered by {})",
            key,
            source
        )
    })?;

    log::debug!("Executing passphrase command for key '{}': {}", key, command);

    // Execute command using shell to support pipes and complex commands
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .with_context(|| {
            format!(
                "Failed to execute passphrase command (triggered by {})\nCommand: {}",
                source,
                command
            )
        })?;

    if !output.status.success() {
        bail!(
            "Passphrase command failed (triggered by {})\nCommand: {}\nExit code: {}\nstderr: {}",
            source,
            command,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Parse and sanitize passphrase
    let passphrase = String::from_utf8(output.stdout)
        .with_context(|| {
            format!(
                "Passphrase command output is not valid UTF-8 (triggered by {})\nCommand: {}",
                source,
                command
            )
        })?
        .trim()
        .to_string();

    if passphrase.is_empty() {
        bail!(
            "Passphrase command returned empty output (triggered by {})\nCommand: {}",
            source,
            command
        );
    }

    // TODO: Additional passphrase sanitization if needed
    // For now we just trim whitespace which is the most common issue

    log::debug!("Setting AGE_PASSPHRASE from passphrase getter '{}'", key);
    std::env::set_var("AGE_PASSPHRASE", passphrase);

    Ok(())
}
