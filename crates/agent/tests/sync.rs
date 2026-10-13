//! Two devices syncing through a real server, each with its own agent.

use std::net::TcpListener;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use silo_agent::protocol::{AgentError, ListFilter, NewSecret, Reply, Request, SecretUpdate};
use silo_agent::server::{self, Config};
use silo_agent::sync::SyncReport;
use silo_agent::{Client, ClientError, Paths, Store};
use silo_core::AccountRecord;
use silo_core::crypto::KdfParams;
use silo_core::vault::{
    FolderPath, Grant, Note, SealedSecret, SecretBody, SecretKind, SecretMeta, StoredSecret,
};
use silo_server::{AppState, Db, accounts};

const PASSWORD: &str = "correct horse";

struct Server {
    url: String,
    db: Db,
}

impl Server {
    fn start() -> Self {
        let db = Db::open_in_memory().unwrap();
        let state = AppState::new(db.clone()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, silo_server::app(state))
                    .await
                    .unwrap();
            });
        });
        Self {
            url: format!("http://127.0.0.1:{port}"),
            db,
        }
    }

    fn invite(&self) -> String {
        self.db
            .with(|conn| accounts::create_invite(conn, &mut rand::rng(), silo_agent::unix_now(), 7))
            .unwrap()
    }
}

struct Device {
    _dir: tempfile::TempDir,
    paths: Paths,
    client: Client,
    agent: Option<JoinHandle<std::io::Result<()>>>,
}

impl Device {
    fn start(with_account: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        let store = Store::open(paths.clone()).unwrap();
        if with_account {
            let mut rng = rand::rng();
            let kdf = KdfParams::recommended(&mut rng);
            let (record, _) = AccountRecord::create(&mut rng, PASSWORD.as_bytes(), kdf).unwrap();
            store.write_account(&record).unwrap();
        }
        let agent = thread::spawn(move || {
            server::run(Config {
                store,
                default_ttl: server::DEFAULT_TTL,
                sync_interval: None,
            })
        });
        let client = (0..200)
            .find_map(|_| {
                Client::connect(paths.socket_file())
                    .inspect_err(|_| thread::sleep(Duration::from_millis(10)))
                    .ok()
            })
            .expect("agent came up");
        let mut device = Self {
            _dir: dir,
            paths,
            client,
            agent: Some(agent),
        };
        if with_account {
            device.call(Request::Unlock {
                password: PASSWORD.into(),
                ttl_secs: None,
            });
        }
        device
    }

    fn call(&mut self, request: Request) -> Reply {
        self.client.call(&request).unwrap()
    }

    fn try_call(&mut self, request: Request) -> Result<Reply, ClientError> {
        self.client.call(&request)
    }

    fn sync(&mut self) -> SyncReport {
        match self.call(Request::Sync) {
            Reply::Synced(report) => report,
            other => panic!("{other:?}"),
        }
    }

    fn add_note(&mut self, path: &str, text: &str) {
        let (folder, title) = path.rsplit_once('/').unwrap();
        self.call(Request::Add(NewSecret {
            title: title.into(),
            folder: FolderPath::parse(folder).unwrap(),
            tags: vec![],
            urls: vec![],
            basic_auth: false,
            body: note(text),
        }));
    }

    fn edit_note(&mut self, path: &str, text: &str) {
        self.call(Request::Update(SecretUpdate {
            selector: path.into(),
            revision: None,
            title: None,
            folder: None,
            tags: None,
            urls: None,
            basic_auth: None,
            body: Some(note(text)),
        }));
    }

    fn text(&mut self, path: &str) -> Option<String> {
        match self.try_call(Request::Get {
            selector: path.into(),
        }) {
            Ok(Reply::Secret(view)) => Some(note_text(&view.body)),
            Err(ClientError::Agent(AgentError::NotFound { .. })) => None,
            other => panic!("{other:?}"),
        }
    }

    /// The current text and every earlier one.
    fn all_texts(&mut self, path: &str) -> Vec<String> {
        let mut texts = vec![self.text(path).unwrap()];
        if let Reply::History(views) = self.call(Request::History {
            selector: path.into(),
        }) {
            texts.extend(views.iter().map(|v| note_text(&v.body)));
        }
        texts
    }

    fn paths_listed(&mut self) -> Vec<String> {
        match self.call(Request::List(ListFilter::default())) {
            Reply::List(list) => list.iter().map(|s| s.path()).collect(),
            other => panic!("{other:?}"),
        }
    }

    fn register(&mut self, server: &Server, username: &str) {
        let reply = self.call(Request::SyncRegister {
            server: server.url.clone(),
            username: username.into(),
            invite: server.invite(),
            password: PASSWORD.into(),
            device_name: Some("first".into()),
        });
        assert!(matches!(reply, Reply::SyncStatus(Some(_))), "{reply:?}");
    }

    fn login(&mut self, server: &Server, username: &str) {
        let reply = self.call(Request::SyncLogin {
            server: server.url.clone(),
            username: username.into(),
            password: PASSWORD.into(),
            device_name: Some("second".into()),
        });
        assert!(matches!(reply, Reply::SyncStatus(Some(_))), "{reply:?}");
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        let _ = self.client.call(&Request::Shutdown);
        if let Some(agent) = self.agent.take() {
            let _ = agent.join();
        }
    }
}

fn note(text: &str) -> SecretBody {
    SecretBody::Note(Note { text: text.into() })
}

fn note_text(body: &SecretBody) -> String {
    match body {
        SecretBody::Note(note) => note.text.clone(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn two_devices_stay_in_step() {
    let server = Server::start();
    let mut laptop = Device::start(true);
    laptop.add_note("notes/one", "1");
    laptop.add_note("notes/two", "2");
    laptop.register(&server, "nikita");
    let report = laptop.sync();
    assert_eq!(report.pushed, 2, "{report:?}");
    assert_eq!(laptop.sync(), SyncReport::default());

    // A new machine gets the account and everything in it.
    let mut desktop = Device::start(false);
    desktop.login(&server, "nikita");
    assert!(desktop.paths.account_file().is_file());
    let report = desktop.sync();
    assert_eq!(report.pulled, 2, "{report:?}");
    assert_eq!(desktop.paths_listed(), laptop.paths_listed());
    let Reply::Status(laptop_status) = laptop.call(Request::Status) else {
        panic!()
    };
    let Reply::Status(desktop_status) = desktop.call(Request::Status) else {
        panic!()
    };
    assert_eq!(laptop_status.fingerprint, desktop_status.fingerprint);

    // An edit travels, and the old revision stays in history.
    desktop.edit_note("notes/one", "1b");
    assert_eq!(desktop.sync().pushed, 1);
    assert_eq!(laptop.sync().pulled, 1);
    assert_eq!(laptop.text("notes/one").as_deref(), Some("1b"));
    assert_eq!(laptop.all_texts("notes/one"), ["1b", "1"]);

    // So does a deletion.
    laptop.call(Request::Remove {
        selector: "notes/two".into(),
    });
    assert_eq!(laptop.sync().pushed, 1);
    assert_eq!(desktop.sync().removed, 1);
    assert_eq!(desktop.text("notes/two"), None);

    // Status, devices, revoking.
    let Reply::SyncStatus(Some(status)) = desktop.call(Request::SyncStatus) else {
        panic!()
    };
    assert_eq!(status.username, "nikita");
    assert_eq!(status.pending, Some(0));
    assert!(status.last_sync.is_some() && status.last_error.is_none());
    let Reply::Devices(devices) = laptop.call(Request::SyncDevices) else {
        panic!()
    };
    assert_eq!(devices.len(), 2);
    let other = devices.iter().find(|d| !d.current).unwrap();
    assert_eq!(other.name, "second");
    laptop.call(Request::SyncRevokeDevice {
        device_id: other.id.clone(),
    });
    let err = desktop.try_call(Request::Sync).unwrap_err().to_string();
    assert!(err.contains("revoked"), "{err}");
    let Reply::SyncStatus(Some(status)) = desktop.call(Request::SyncStatus) else {
        panic!()
    };
    assert!(status.last_error.is_some());

    // Logging out keeps the vault.
    assert_eq!(
        desktop.call(Request::SyncLogout),
        Reply::LoggedOut { revoked: true }
    );
    assert_eq!(desktop.call(Request::SyncStatus), Reply::SyncStatus(None));
    assert_eq!(desktop.text("notes/one").as_deref(), Some("1b"));
    assert!(!desktop.paths.sync_file().exists());
}

#[test]
fn wrong_password_and_other_accounts_are_refused() {
    let server = Server::start();
    let mut laptop = Device::start(true);
    laptop.register(&server, "nikita");

    let mut stranger = Device::start(false);
    let err = stranger
        .try_call(Request::SyncLogin {
            server: server.url.clone(),
            username: "nikita".into(),
            password: "wrong".into(),
            device_name: None,
        })
        .unwrap_err()
        .to_string();
    assert!(err.contains("wrong username or password"), "{err}");
    assert!(!stranger.paths.account_file().exists());

    // A machine with its own account cannot log in to another one.
    let mut other = Device::start(true);
    let err = other
        .try_call(Request::SyncLogin {
            server: server.url.clone(),
            username: "nikita".into(),
            password: PASSWORD.into(),
            device_name: None,
        })
        .unwrap_err()
        .to_string();
    assert!(err.contains("different account"), "{err}");
    // And that attempt did not leave a device behind.
    let Reply::Devices(devices) = laptop.call(Request::SyncDevices) else {
        panic!()
    };
    assert_eq!(devices.len(), 1);
}

#[test]
fn conflicts_keep_both_versions() {
    let server = Server::start();
    let mut laptop = Device::start(true);
    laptop.add_note("notes/shared", "base");
    laptop.register(&server, "nikita");
    laptop.sync();
    let mut desktop = Device::start(false);
    desktop.login(&server, "nikita");
    desktop.sync();

    // Both edit the same secret before syncing.
    laptop.edit_note("notes/shared", "from laptop");
    desktop.edit_note("notes/shared", "from desktop");
    laptop.sync();
    let report = desktop.sync();
    assert_eq!(report.conflicts.len(), 1, "{report:?}");
    laptop.sync();

    // Both end up with the same current version, and both edits are in
    // history on both machines.
    let current = laptop.text("notes/shared");
    assert_eq!(desktop.text("notes/shared"), current);
    for device in [&mut laptop, &mut desktop] {
        let texts = device.all_texts("notes/shared");
        assert!(texts.contains(&"from laptop".to_owned()), "{texts:?}");
        assert!(texts.contains(&"from desktop".to_owned()), "{texts:?}");
        assert!(texts.contains(&"base".to_owned()), "{texts:?}");
    }

    // Deleted on one, edited on the other: the edit wins on both.
    laptop.call(Request::Remove {
        selector: "notes/shared".into(),
    });
    desktop.edit_note("notes/shared", "still needed");
    laptop.sync();
    let report = desktop.sync();
    assert_eq!(report.conflicts.len(), 1, "{report:?}");
    assert_eq!(laptop.sync().pulled, 1);
    assert_eq!(laptop.text("notes/shared").as_deref(), Some("still needed"));

    // Edited on one, deleted on the other, the deletion pushed second: the
    // edit wins again.
    laptop.edit_note("notes/shared", "edited first");
    laptop.sync();
    desktop.call(Request::Remove {
        selector: "notes/shared".into(),
    });
    let report = desktop.sync();
    assert_eq!(report.conflicts.len(), 1, "{report:?}");
    assert_eq!(
        desktop.text("notes/shared").as_deref(),
        Some("edited first")
    );
    assert_eq!(laptop.sync(), SyncReport::default());
}

#[test]
fn every_offline_edit_survives_a_conflict() {
    let server = Server::start();
    let mut laptop = Device::start(true);
    laptop.add_note("notes/shared", "base");
    laptop.register(&server, "nikita");
    laptop.sync();
    let mut desktop = Device::start(false);
    desktop.login(&server, "nikita");
    desktop.sync();

    // Two edits on the laptop while the desktop's edit gets there first.
    laptop.edit_note("notes/shared", "laptop 1");
    laptop.edit_note("notes/shared", "laptop 2");
    desktop.edit_note("notes/shared", "desktop");
    desktop.sync();
    let report = laptop.sync();
    assert_eq!(report.conflicts.len(), 1, "{report:?}");
    desktop.sync();

    let current = laptop.text("notes/shared");
    assert_eq!(desktop.text("notes/shared"), current);
    for device in [&mut laptop, &mut desktop] {
        let mut texts = device.all_texts("notes/shared");
        texts.sort();
        texts.dedup();
        assert_eq!(texts, ["base", "desktop", "laptop 1", "laptop 2"]);
    }
}

#[test]
fn edits_made_while_logged_out_survive_logging_in_again() {
    // Without the baseline, as after a logout by an older version.
    for keep_baseline in [true, false] {
        let server = Server::start();
        let mut laptop = Device::start(true);
        laptop.add_note("notes/shared", "base");
        laptop.add_note("notes/other", "other");
        laptop.register(&server, "nikita");
        laptop.sync();
        let mut desktop = Device::start(false);
        desktop.login(&server, "nikita");
        desktop.sync();

        laptop.call(Request::SyncLogout);
        if !keep_baseline {
            std::fs::remove_file(laptop.paths.sync_baseline_file()).unwrap();
        }
        laptop.edit_note("notes/shared", "laptop 1");
        laptop.edit_note("notes/shared", "laptop 2");
        laptop.call(Request::Remove {
            selector: "notes/other".into(),
        });
        desktop.edit_note("notes/shared", "desktop");
        desktop.sync();

        laptop.login(&server, "nikita");
        let report = laptop.sync();
        assert_eq!(report.conflicts.len(), 1, "{report:?}");
        desktop.sync();
        let current = laptop.text("notes/shared");
        assert_eq!(desktop.text("notes/shared"), current);
        for device in [&mut laptop, &mut desktop] {
            let mut texts = device.all_texts("notes/shared");
            texts.sort();
            texts.dedup();
            assert_eq!(texts, ["base", "desktop", "laptop 1", "laptop 2"]);
        }
        // Only the baseline knows the server had what was deleted meanwhile.
        if keep_baseline {
            assert_eq!(desktop.text("notes/other"), None);
            assert_eq!(laptop.text("notes/other"), None);
        }
    }
}

#[test]
fn an_offline_edit_restores_a_secret_deleted_after_another_edit() {
    let server = Server::start();
    let mut laptop = Device::start(true);
    laptop.add_note("notes/shared", "base");
    laptop.register(&server, "nikita");
    laptop.sync();
    let mut desktop = Device::start(false);
    desktop.login(&server, "nikita");
    desktop.sync();

    // The desktop edits and then deletes while the laptop edits offline: the
    // deleted revision has the same number as the laptop's edit, then a
    // higher one.
    for edits in [1, 2] {
        laptop.edit_note("notes/shared", &format!("offline {edits}"));
        for n in 0..edits {
            desktop.edit_note("notes/shared", &format!("desktop {n}"));
        }
        desktop.sync();
        desktop.call(Request::Remove {
            selector: "notes/shared".into(),
        });
        desktop.sync();

        let report = laptop.sync();
        assert_eq!(report.conflicts.len(), 1, "{report:?}");
        assert_eq!(report.pushed, 1, "{report:?}");
        desktop.sync();
        let expected = format!("offline {edits}");
        assert_eq!(desktop.text("notes/shared"), Some(expected.clone()));
        assert_eq!(laptop.text("notes/shared"), Some(expected));
        assert_eq!(laptop.sync(), SyncReport::default());
        assert_eq!(desktop.sync(), SyncReport::default());
    }
}

#[test]
fn revisions_not_signed_by_the_account_are_ignored() {
    let server = Server::start();
    let mut laptop = Device::start(true);
    laptop.add_note("notes/target", "genuine");
    laptop.register(&server, "nikita");
    laptop.sync();
    let mut desktop = Device::start(false);
    desktop.login(&server, "nikita");
    desktop.sync();

    // A compromised server writes revision 2, sealed and granted to the
    // account's public key but signed by someone else.
    let store = Store::open(laptop.paths.clone()).unwrap();
    let genuine = store.load_all().unwrap().remove(0);
    let recipient = genuine.grants[0].recipient;
    let mut rng = rand::rng();
    let kdf = KdfParams::new(&mut rng, 256, 1, 1);
    let (_, mallory) = AccountRecord::create(&mut rng, b"x", kdf).unwrap();
    let meta = forged_meta();
    let (secret, key) = SealedSecret::seal(
        &mut rng,
        &mallory,
        genuine.secret.id,
        2,
        &meta,
        &note("evil"),
    )
    .unwrap();
    let grant = Grant::seal(&mut rng, &mallory, &secret, &key, recipient).unwrap();
    let forged = StoredSecret {
        secret,
        grants: vec![grant],
    };
    let id = genuine.secret.id.to_string();
    server
        .db
        .with(move |conn| {
            conn.execute(
                "INSERT INTO revisions (secret_id, revision, author_id, data, created_at)
                 VALUES (?1, 2, 1, ?2, 0)",
                (&id, serde_json::to_string(&forged.secret).unwrap()),
            )?;
            conn.execute(
                "INSERT INTO grants (secret_id, revision, recipient, data) VALUES (?1, 2, ?2, ?3)",
                (
                    &id,
                    &forged.grants[0].recipient.as_bytes()[..],
                    serde_json::to_string(&forged.grants[0]).unwrap(),
                ),
            )?;
            conn.execute(
                "UPDATE secrets SET current_revision = 2, seq = seq + 100 WHERE id = ?1",
                [&id],
            )?;
            Ok(())
        })
        .unwrap();

    let report = desktop.sync();
    assert_eq!(report.skipped, 1, "{report:?}");
    assert_eq!(desktop.text("notes/target").as_deref(), Some("genuine"));
}

/// Metadata for a forged note; its content does not matter.
fn forged_meta() -> SecretMeta {
    SecretMeta {
        title: "target".into(),
        kind: SecretKind::Note,
        folder: FolderPath::parse("notes").unwrap(),
        tags: vec![],
        urls: vec![],
        basic_auth: false,
        created_at: 0,
        updated_at: 0,
    }
}
