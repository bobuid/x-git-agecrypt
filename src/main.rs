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

fn resolve_passphrase(args: &cli::Args, repo: &impl Repository) -> Result<()> {
    // Load config to check [passphrase] section
    let cfg = AppConfig::load(&PathBuf::from("git-agecrypt.toml"), repo.workdir())?;

    // Determine which key to use:
    // 1. Explicit -g <key> argument
    // 2. Implicit "sops" key if present in config
    let getter_key = args.passphrase_getter.as_deref()
        .or_else(|| cfg.has_passphrase_key("sops").then_some("sops"));

    let Some(key) = getter_key else {
        return Ok(());
    };

    let command = cfg.get_passphrase_command(key).ok_or_else(|| {
        anyhow::anyhow!(
            "Passphrase getter '{}' not found in [passphrase] section of git-agecrypt.toml",
            key
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
                "Failed to execute passphrase command ({}): {}",
                if args.passphrase_getter.is_some() {
                    format!("-g {}", key)
                } else {
                    "implicit sops key".to_string()
                },
                command
            )
        })?;

    if !output.status.success() {
        bail!(
            "Passphrase command failed (triggered by {})\nCommand: {}\nExit code: {}\nstderr: {}",
            if args.passphrase_getter.is_some() {
                format!("-g {}", key)
            } else {
                "implicit sops key in [passphrase] section".to_string()
            },
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
                if args.passphrase_getter.is_some() {
                    format!("-g {}", key)
                } else {
                    "implicit sops key".to_string()
                },
                command
            )
        })?
        .trim()
        .to_string();

    if passphrase.is_empty() {
        bail!(
            "Passphrase command returned empty output (triggered by {})\nCommand: {}",
            if args.passphrase_getter.is_some() {
                format!("-g {}", key)
            } else {
                "implicit sops key in [passphrase] section".to_string()
            },
            command
        );
    }

    // TODO: Additional passphrase sanitization if needed
    // For now we just trim whitespace which is the most common issue

    log::debug!("Setting AGE_PASSPHRASE from passphrase getter '{}'", key);
    std::env::set_var("AGE_PASSPHRASE", passphrase);

    Ok(())
}
