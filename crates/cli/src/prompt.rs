use std::io::{self, BufRead, Write};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

/// Env var that bypasses the password prompt, for scripts and CI.
pub const PASSWORD_ENV: &str = "SECRET_PASSWORD";
const MIN_PASSWORD_LEN: usize = 8;

pub fn password(label: &str) -> Result<Zeroizing<String>> {
    if let Ok(password) = std::env::var(PASSWORD_ENV) {
        return Ok(Zeroizing::new(password));
    }
    let password = rpassword::prompt_password(format!("{label}: ")).context("reading password")?;
    Ok(Zeroizing::new(password))
}

pub fn new_password() -> Result<Zeroizing<String>> {
    if let Ok(password) = std::env::var(PASSWORD_ENV) {
        check_strength(&password)?;
        return Ok(Zeroizing::new(password));
    }
    let first = Zeroizing::new(
        rpassword::prompt_password("New master password: ").context("reading password")?,
    );
    check_strength(&first)?;
    let second =
        Zeroizing::new(rpassword::prompt_password("Repeat: ").context("reading password")?);
    if *first != *second {
        bail!("passwords do not match");
    }
    Ok(first)
}

fn check_strength(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        bail!("master password must be at least {MIN_PASSWORD_LEN} characters");
    }
    Ok(())
}

pub fn confirm(question: &str) -> Result<bool> {
    print!("{question} [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}
