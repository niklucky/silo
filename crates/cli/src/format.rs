//! Output formatting: tables, timestamps, dotenv and shell quoting.

use std::time::{Duration, UNIX_EPOCH};

use secret_core::vault::{SecretBody, SecretKind};

pub fn kind_name(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::Login => "login",
        SecretKind::Card => "card",
        SecretKind::EnvSet => "env",
        SecretKind::File => "file",
        SecretKind::Note => "note",
    }
}

pub fn timestamp(unix_secs: u64) -> String {
    humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(unix_secs)).to_string()
}

pub fn duration(d: Duration) -> String {
    let whole_minutes = Duration::from_secs(d.as_secs() / 60 * 60);
    if whole_minutes.is_zero() {
        return "under a minute".to_owned();
    }
    humantime::format_duration(whole_minutes).to_string()
}

/// Renders rows as aligned columns. `header` is printed first.
pub fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let columns = header.len();
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(columns) {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let render = |cells: &[String]| {
        let mut line = String::new();
        for (i, cell) in cells.iter().enumerate().take(columns) {
            if i > 0 {
                line.push_str("  ");
            }
            if i + 1 == columns {
                line.push_str(cell);
            } else {
                line.push_str(&format!("{cell:<width$}", width = widths[i]));
            }
        }
        line.trim_end().to_owned()
    };
    let header_cells: Vec<String> = header.iter().map(|h| (*h).to_owned()).collect();
    let mut out = render(&header_cells);
    for row in rows {
        out.push('\n');
        out.push_str(&render(row));
    }
    out
}

/// `KEY=value` with dotenv-compatible quoting.
pub fn dotenv_line(key: &str, value: &str) -> String {
    let plain = !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '@' | '+' | ',')
        });
    if plain {
        format!("{key}={value}")
    } else {
        let escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "\\$")
            .replace('\n', "\\n")
            .replace('\r', "\\r");
        format!("{key}=\"{escaped}\"")
    }
}

/// `export KEY='value'` safe for POSIX shells.
pub fn shell_line(key: &str, value: &str) -> String {
    format!("export {key}='{}'", value.replace('\'', "'\\''"))
}

/// Looks up a single field of a body by name, for `secret get --field`.
pub fn field(body: &SecretBody, name: &str) -> Option<String> {
    match body {
        SecretBody::Login(login) => match name {
            "username" => Some(login.username.clone()),
            "password" => Some(login.password.clone()),
            "totp" => login.totp.clone(),
            "notes" => Some(login.notes.clone()),
            _ => None,
        },
        SecretBody::Card(card) => match name {
            "holder" => Some(card.holder.clone()),
            "number" => Some(card.number.clone()),
            "expiry" => Some(format!("{:02}/{}", card.expiry_month, card.expiry_year)),
            "cvv" => Some(card.cvv.clone()),
            "notes" => Some(card.notes.clone()),
            _ => None,
        },
        SecretBody::EnvSet(set) => set
            .vars
            .iter()
            .find(|v| v.key == name)
            .map(|v| v.value.clone()),
        SecretBody::File(file) => match name {
            "name" => Some(file.name.clone()),
            "mime" => file.mime.clone(),
            _ => None,
        },
        SecretBody::Note(note) => match name {
            "text" => Some(note.text.clone()),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_quoting() {
        assert_eq!(dotenv_line("A", "plain_value-1.2"), "A=plain_value-1.2");
        assert_eq!(
            dotenv_line("A", "postgres://u:p@h/db"),
            "A=postgres://u:p@h/db"
        );
        assert_eq!(dotenv_line("A", ""), r#"A="""#);
        assert_eq!(dotenv_line("A", "has space"), r#"A="has space""#);
        assert_eq!(dotenv_line("A", "q\"$\\\n"), r#"A="q\"\$\\\n""#);
    }

    #[test]
    fn shell_quoting() {
        assert_eq!(shell_line("A", "it's"), "export A='it'\\''s'");
    }

    #[test]
    fn table_alignment() {
        let out = table(
            &["PATH", "KIND"],
            &[
                vec!["a/b".into(), "env".into()],
                vec!["longer/path".into(), "note".into()],
            ],
        );
        assert_eq!(
            out,
            "PATH         KIND\na/b          env\nlonger/path  note"
        );
    }

    #[test]
    fn durations_round_to_minutes() {
        assert_eq!(duration(Duration::from_secs(59)), "under a minute");
        assert_eq!(
            duration(Duration::from_secs(11 * 3600 + 32 * 60 + 10)),
            "11h 32m"
        );
    }
}
