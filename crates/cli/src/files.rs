//! Exact file round trips. Bindings contain only metadata and hashes, never values.
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use silo_agent::Paths;
use silo_agent::protocol::{Reply, Request, SecretView};
use silo_core::vault::SecretBody;

use crate::commands::{connected, unexpected};

#[derive(Serialize, Deserialize)]
struct Binding {
    scope: String,
    id: String,
    version: String,
    content_hash: String,
}

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn scope() -> Result<String> {
    let Reply::Status(status) = connected()?.call(&Request::Status)? else {
        bail!("unexpected status reply");
    };
    status.fingerprint.context("vault is locked")
}

fn binding_path(file: &Path) -> Result<PathBuf> {
    // Resolve the parent, not the final file: new pull destinations do not exist
    // yet, and final-component symlinks are explicitly rejected before writes.
    let parent = file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let absolute = fs::canonicalize(parent)?.join(file.file_name().context("expected a filename")?);
    use std::os::unix::ffi::OsStrExt;
    Ok(Paths::from_env()?
        .home()
        .join("files")
        .join(format!("{}.json", hash(absolute.as_os_str().as_bytes()))))
}

fn load_binding(path: &Path, scope: &str, id: &str) -> Result<Option<Binding>> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let binding: Binding = serde_json::from_slice(&data).context("reading file baseline")?;
    Ok(
        ((binding.scope == scope || binding.scope.rsplit('|').next() == Some(scope))
            && binding.id == id)
            .then_some(binding),
    )
}

fn atomic_write(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if let Ok(meta) = fs::symlink_metadata(path)
        && !meta.file_type().is_file()
    {
        bail!("{} is not a regular file", path.display());
    }
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    if overwrite {
        temp.persist(path)?;
    } else {
        temp.persist_noclobber(path)?;
    }
    Ok(())
}

fn save_binding(path: &Path, binding: &Binding) -> Result<()> {
    let parent = path.parent().context("missing baseline directory")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    atomic_write(path, &serde_json::to_vec(binding)?, true)
}

pub fn snapshot(selector: &str) -> Result<(SecretView, String)> {
    match connected()?.call(&Request::FileSnapshot {
        selector: selector.to_owned(),
    })? {
        Reply::FileSnapshot { secret, version } => Ok((*secret, version)),
        other => Err(unexpected(other)),
    }
}

fn load_file_binding(file: &Path, id: &str) -> Result<Option<Binding>> {
    let path = binding_path(file)?;
    let scope = scope()?;
    if let Some(binding) = load_binding(&path, &scope, id)? {
        return Ok(Some(binding));
    }
    // Keep safeguards for files previously pulled with the short-lived env
    // commands. Only metadata moves; the stored secret remains a normal file.
    let legacy = Paths::from_env()?
        .home()
        .join("env-files")
        .join(path.file_name().context("expected baseline filename")?);
    load_binding(&legacy, &scope, id)
}

pub fn record(file: &Path, secret: &SecretView, version: String) -> Result<()> {
    let SecretBody::File(body) = &secret.body else {
        bail!("expected a file");
    };
    save_binding(
        &binding_path(file)?,
        &Binding {
            scope: scope()?,
            id: secret.id.to_string(),
            version,
            content_hash: hash(&body.data),
        },
    )
}

/// An untracked source is an explicit replacement of the current snapshot;
/// a tracked source must be based on that exact sealed revision.
pub fn expected(file: &Path, secret: &SecretView, current: &str, force: bool) -> Result<String> {
    if !force && let Some(binding) = load_file_binding(file, &secret.id.to_string())? {
        if binding.version != current {
            bail!(
                "the file changed in the vault since this copy was read; pull to another path and merge, or use --force to replace it deliberately"
            );
        }
        return Ok(binding.version);
    }
    Ok(current.to_owned())
}

pub fn add(path: &str, file: &Path, tags: &[String], local_only: bool) -> Result<()> {
    use silo_agent::protocol::NewSecret;
    use silo_core::vault::File;
    let (folder, title) = crate::commands::split_path(path)?;
    let data = fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let original_hash = hash(&data);
    let new = NewSecret {
        title,
        folder,
        tags: crate::commands::tags(tags)?,
        urls: vec![],
        basic_auth: false,
        body: SecretBody::File(File {
            name: file
                .file_name()
                .context("expected a filename")?
                .to_string_lossy()
                .into_owned(),
            mime: None,
            data,
        }),
    };
    let reply = connected()?.call(&if local_only {
        Request::AddLocal(new)
    } else {
        Request::Add(new)
    })?;
    let Reply::Added(summary) = reply else {
        return Err(unexpected(reply));
    };
    let (secret, version) = snapshot(&summary.id.to_string())?;
    let SecretBody::File(body) = &secret.body else {
        bail!("expected a file");
    };
    if secret.revision != summary.revision || hash(&body.data) != original_hash {
        bail!(
            "file was added, but changed again before its baseline could be saved; export the current revision before editing"
        );
    }
    record(file, &secret, version)
        .context("file was added, but its baseline could not be saved")?;
    println!(
        "Added {} (file{}) id {}",
        summary.path(),
        if local_only { ", local-only" } else { "" },
        summary.id
    );
    Ok(())
}

pub fn pull(selector: &str, output: Option<PathBuf>, force: bool) -> Result<()> {
    let (secret, version) = snapshot(selector)?;
    let SecretBody::File(body) = &secret.body else {
        bail!("expected a file");
    };
    let target = match output {
        Some(output) => output,
        None => {
            let name = Path::new(&body.name);
            if name.file_name().is_none()
                || name.file_name() != Some(name.as_os_str())
                || body.name == "."
                || body.name == ".."
            {
                bail!("the stored filename is not a safe basename; choose an output with -o");
            }
            PathBuf::from(&body.name)
        }
    };
    let baseline = load_file_binding(&target, &secret.id.to_string())?;
    write_pulled(&target, &body.data, baseline.as_ref(), force)?;
    record(&target, &secret, version)
        .context("file was written, but its baseline could not be saved")?;
    println!(
        "Wrote {} ({} bytes; revision {})",
        target.display(),
        body.data.len(),
        secret.revision
    );
    Ok(())
}

fn write_pulled(file: &Path, data: &[u8], baseline: Option<&Binding>, force: bool) -> Result<()> {
    let existing = match fs::read(file) {
        Ok(bytes) => Some(bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err.into()),
    };
    if !force && let Some(bytes) = &existing {
        let tracked_unchanged = baseline.is_some_and(|b| hash(bytes) == b.content_hash);
        if !tracked_unchanged && bytes != data {
            bail!(
                "{} has local changes or is not tracked for this document; use --force to overwrite",
                file.display()
            );
        }
    }
    atomic_write(file, data, existing.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline(bytes: &[u8]) -> Binding {
        Binding {
            scope: "server|alice|fingerprint".into(),
            id: "id".into(),
            version: "version".into(),
            content_hash: hash(bytes),
        }
    }

    #[test]
    fn pull_preserves_local_edits_and_writes_exact_bytes_with_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".env");
        let original = b"# original\r\nA='one'\r\n\r\n";
        write_pulled(&file, original, None, false).unwrap();
        let binding = baseline(original);
        assert_eq!(fs::read(&file).unwrap(), original);
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let edited = b"# local comment changed\nA=one\n";
        fs::write(&file, edited).unwrap();
        assert!(write_pulled(&file, b"A=remote\n", Some(&binding), false).is_err());
        assert_eq!(fs::read(&file).unwrap(), edited);
        assert!(write_pulled(&file, b"A=remote\n", None, false).is_err());
        write_pulled(&file, b"A=remote\n", Some(&binding), true).unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"A=remote\n");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let binding = baseline(b"A=remote\n");
        write_pulled(&file, original, Some(&binding), false).unwrap();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn pull_refuses_symlinks_and_atomic_create_does_not_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"keep").unwrap();
        let link = dir.path().join(".env");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_pulled(&link, b"new", None, true).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        assert!(atomic_write(&target, b"new", false).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn baselines_are_scoped_to_the_server_account_and_document() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binding.json");
        let binding = baseline(b"SECRET=synthetic");
        save_binding(&path, &binding).unwrap();
        assert!(load_binding(&path, &binding.scope, "id").unwrap().is_some());
        assert!(load_binding(&path, &binding.scope, "id").unwrap().is_some());
        assert!(
            load_binding(&path, "other-account", "id")
                .unwrap()
                .is_none()
        );
        assert!(
            load_binding(&path, &binding.scope, "api/prod")
                .unwrap()
                .is_none()
        );
        assert!(
            !fs::read_to_string(path)
                .unwrap()
                .contains("SECRET=synthetic")
        );
    }
}
