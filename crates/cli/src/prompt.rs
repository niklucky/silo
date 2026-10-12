use std::io::{self, BufRead, Write};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

/// Env var that bypasses the password prompt, for scripts and CI.
pub const PASSWORD_ENV: &str = "SILO_PASSWORD";
const MIN_PASSWORD_LEN: usize = 8;

pub fn password(label: &str) -> Result<Zeroizing<String>> {
    if let Ok(password) = std::env::var(PASSWORD_ENV) {
        return Ok(Zeroizing::new(password));
    }
    let password = rpassword::prompt_password(format!("{label}: ")).context("reading password")?;
    Ok(Zeroizing::new(password))
}

/// A hidden answer. Unlike [`password`], never taken from SILO_PASSWORD,
/// which holds the master password.
pub fn hidden(label: &str) -> Result<Zeroizing<String>> {
    let answer = rpassword::prompt_password(format!("{label}: ")).context("reading password")?;
    Ok(Zeroizing::new(answer))
}

/// A new secret value, typed twice.
pub fn new_secret(label: &str) -> Result<Zeroizing<String>> {
    let first = hidden(label)?;
    if first.is_empty() {
        bail!("empty password");
    }
    if *hidden("Repeat")? != *first {
        bail!("passwords do not match");
    }
    Ok(first)
}

/// One line, shown with the current value; `None` when the answer is empty.
pub fn line(label: &str, current: &str) -> Result<Option<String>> {
    if current.is_empty() {
        print!("{label}: ");
    } else {
        print!("{label} [{current}]: ");
    }
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    let answer = answer.trim();
    Ok((!answer.is_empty()).then(|| answer.to_owned()))
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
