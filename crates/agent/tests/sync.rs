//! Two devices syncing through a real server, each with its own agent.

use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
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
    fail_pushes: Arc<AtomicBool>,
}

impl Server {
    fn start() -> Self {
        let db = Db::open_in_memory().unwrap();
        let state = AppState::new(db.clone()).unwrap();
        let fail_pushes = Arc::new(AtomicBool::new(false));
        let failures = Arc::clone(&fail_pushes);
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
                let app = silo_server::app(state).layer(axum::middleware::from_fn(
                    move |request: axum::extract::Request, next: axum::middleware::Next| {
                        let failures = Arc::clone(&failures);
                        async move {
                            if request.uri().path() == "/v1/push" && failures.load(Ordering::SeqCst)
                            {
                                axum::response::IntoResponse::into_response(
                                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                                )
                            } else {
                                next.run(request).await
                            }
                        }
                    },
                ));
                axum::serve(listener, app).await.unwrap();
            });
        });
        Self {
            url: format!("http://127.0.0.1:{port}"),
            db,
            fail_pushes,
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

    fn restart(&mut self) {
        self.call(Request::Shutdown);
        self.agent.take().unwrap().join().unwrap().unwrap();
        let store = Store::open(self.paths.clone()).unwrap();
        self.agent = Some(thread::spawn(move || {
            server::run(Config {
                store,
                default_ttl: server::DEFAULT_TTL,
                sync_interval: None,
            })
        }));
        self.client = (0..200)
            .find_map(|_| {
                Client::connect(self.paths.socket_file())
                    .inspect_err(|_| thread::sleep(Duration::from_millis(10)))
                    .ok()
            })
            .expect("restarted agent came up");
        self.call(Request::Unlock {
            password: PASSWORD.into(),
            ttl_secs: None,
        });
    }

    fn call(&mut self, request: Request) -> Reply {
        self.client.call(&request).unwrap()
    }

    fn try_call(&mut self, request: Request) -> Result<Reply, ClientError> {
        self.client.call(&request)
    }

    fn sync(&mut self) -> SyncReport {
        let report = match self.call(Request::Sync) {
            Reply::Synced(report) => report,
            other => panic!("{other:?}"),
        };
        // This same-connection request is a barrier after post-write notice
        // acknowledgment, before tests inspect persistent state directly.
        self.call(Request::SyncStatus);
        report
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

fn file_snapshot(
    device: &mut Device,
    selector: &str,
) -> (silo_agent::protocol::SecretView, String) {
    match device.call(Request::FileSnapshot {
        selector: selector.into(),
    }) {
        Reply::FileSnapshot { secret, version } => (*secret, version),
        other => panic!("unexpected {other:?}"),
    }
}

fn new_file(path: &str, data: &[u8]) -> NewSecret {
    let (folder, title) = path.rsplit_once('/').unwrap_or(("", path));
    NewSecret {
        title: title.into(),
        folder: FolderPath::parse(folder).unwrap(),
        tags: vec![],
        urls: vec![],
        basic_auth: false,
        body: SecretBody::File(silo_core::vault::File {
            name: ".env".into(),
            mime: None,
            data: data.to_vec(),
        }),
    }
}

fn add_file(
    device: &mut Device,
    path: &str,
    data: &[u8],
    local_only: bool,
) -> (silo_agent::protocol::SecretView, String) {
    let new = new_file(path, data);
    let Reply::Added(added) = device.call(if local_only {
        Request::AddLocal(new)
    } else {
        Request::Add(new)
    }) else {
        panic!("not added")
    };
    file_snapshot(device, &added.id.to_string())
}

fn file_update(selector: &str, data: &[u8]) -> SecretUpdate {
    SecretUpdate {
        selector: selector.into(),
        revision: None,
        title: None,
        folder: None,
        tags: None,
        urls: None,
        basic_auth: None,
        body: Some(new_file("file", data).body),
    }
}

fn edit_file(
    device: &mut Device,
    selector: &str,
    data: &[u8],
    expected: &str,
) -> (silo_agent::protocol::SecretView, String) {
    match device.call(Request::UpdateChecked {
        update: file_update(selector, data),
        expected: expected.into(),
    }) {
        Reply::FileSnapshot { secret, version } => (*secret, version),
        other => panic!("unexpected {other:?}"),
    }
}

fn file_bytes(view: &silo_agent::protocol::SecretView) -> &[u8] {
    match &view.body {
        SecretBody::File(file) => &file.data,
        _ => panic!("not a file"),
    }
}

fn fingerprint(device: &Device) -> String {
    Store::open(device.paths.clone())
        .unwrap()
        .read_account()
        .unwrap()
        .unlock(PASSWORD.as_bytes())
        .unwrap()
        .fingerprint()
        .to_string()
}

fn connect_verified(alice: &mut Device, bob: &mut Device) {
    alice.call(Request::Connect {
        username: "bob".into(),
    });
    bob.call(Request::Connect {
        username: "alice".into(),
    });
    alice.call(Request::VerifyPeer {
        username: "bob".into(),
        fingerprint: fingerprint(bob),
    });
    bob.call(Request::VerifyPeer {
        username: "alice".into(),
        fingerprint: fingerprint(alice),
    });
}

#[test]
fn files_work_offline_preserve_bytes_rotate_keys_and_reject_stale_replacements() {
    let mut device = Device::start(true);
    let original =
        b"# database\r\nDB_URL='postgres://localhost/test'\r\n\r\nEMPTY=\r\nDUP=one\r\nDUP=two";
    let (created, initial_version) = add_file(&mut device, "projects/api/dev", original, false);
    let id = created.id.to_string();
    assert_eq!(created.revision, 1);
    assert_eq!(file_bytes(&created), original);
    let store = Store::open(device.paths.clone()).unwrap();
    let before = store.load_all().unwrap().remove(0);
    let keys = store
        .read_account()
        .unwrap()
        .unlock(PASSWORD.as_bytes())
        .unwrap();
    let old_key = before.grants[0].open(&keys).unwrap();
    let replacement = b"# rotated\nDB_URL=postgres://localhost/new\n";
    let (updated, version) = edit_file(&mut device, &id, replacement, &initial_version);
    assert_eq!(updated.revision, 2);
    assert_eq!(file_bytes(&updated), replacement);
    assert!(
        store
            .load_all()
            .unwrap()
            .remove(0)
            .secret
            .open_body(&old_key)
            .is_err()
    );
    assert!(
        device
            .try_call(Request::UpdateChecked {
                update: file_update(&id, b"must-not-win"),
                expected: initial_version
            })
            .is_err()
    );
    let Reply::History(history) = device.call(Request::History {
        selector: id.clone(),
    }) else {
        panic!("no history")
    };
    assert_eq!(file_bytes(&history[0]), original);
    let (empty, _) = edit_file(&mut device, &id, b"", &version);
    assert_eq!(file_bytes(&empty), b"");
    // Sync configuration is optional for creation, replacement and reading.
    assert!(matches!(
        device.call(Request::SyncStatus),
        Reply::SyncStatus(None)
    ));
    let server = Server::start();
    device.register(&server, "alice");
    assert_eq!(device.sync().pushed, 1);
    let mut other = Device::start(false);
    other.login(&server, "alice");
    other.sync();
    assert_eq!(file_bytes(&file_snapshot(&mut other, &id).0), b"");
}

#[test]
fn file_sharing_requires_verified_peers_and_preserves_readonly_access_and_revocation() {
    let server = Server::start();
    let mut alice = Device::start(true);
    let mut bob = Device::start(true);
    alice.register(&server, "alice");
    bob.register(&server, "bob");
    let (created, _) = add_file(&mut alice, "api/prod", b"# prod\nTOKEN=one\n", false);
    let id = created.id.to_string();
    alice.call(Request::Connect {
        username: "bob".into(),
    });
    bob.call(Request::Connect {
        username: "alice".into(),
    });
    assert!(
        alice
            .try_call(Request::Share {
                selector: id.clone(),
                username: "bob".into(),
                revoke: false
            })
            .is_err()
    );
    assert!(
        alice
            .try_call(Request::VerifyPeer {
                username: "bob".into(),
                fingerprint: "wrong".into()
            })
            .is_err()
    );
    alice.call(Request::VerifyPeer {
        username: "bob".into(),
        fingerprint: fingerprint(&bob),
    });
    alice.call(Request::Share {
        selector: id.clone(),
        username: "bob".into(),
        revoke: false,
    });
    assert_eq!(bob.sync().skipped, 1);
    assert!(
        bob.try_call(Request::Get {
            selector: id.clone()
        })
        .is_err()
    );
    bob.call(Request::VerifyPeer {
        username: "alice".into(),
        fingerprint: fingerprint(&alice),
    });
    bob.sync();
    let (shared, baseline) = file_snapshot(&mut bob, &id);
    assert_eq!(file_bytes(&shared), file_bytes(&created));
    assert!(
        bob.try_call(Request::UpdateChecked {
            update: file_update(&id, b"unauthorized"),
            expected: baseline
        })
        .is_err()
    );
    assert!(
        bob.try_call(Request::Remove {
            selector: id.clone()
        })
        .is_err()
    );
    assert!(
        bob.try_call(Request::Share {
            selector: id.clone(),
            username: "alice".into(),
            revoke: false
        })
        .is_err()
    );
    bob.call(Request::Lock);
    bob.call(Request::Unlock {
        password: PASSWORD.into(),
        ttl_secs: None,
    });
    assert!(
        bob.try_call(Request::Update(file_update(&id, b"unauthorized")))
            .is_err()
    );
    assert_eq!(bob.sync().pushed, 0);
    let (_, baseline) = file_snapshot(&mut alice, &id);
    edit_file(&mut alice, &id, b"TOKEN=two\n", &baseline);
    alice.sync();
    bob.sync();
    assert_eq!(file_bytes(&file_snapshot(&mut bob, &id).0), b"TOKEN=two\n");
    alice.call(Request::Share {
        selector: id.clone(),
        username: "bob".into(),
        revoke: true,
    });
    let (_, baseline) = file_snapshot(&mut alice, &id);
    edit_file(&mut alice, &id, b"TOKEN=after-revoke\n", &baseline);
    alice.sync();
    bob.sync();
    assert_eq!(
        file_bytes(&file_snapshot(&mut bob, &id).0),
        b"TOKEN=two\n",
        "old cached copies remain readable"
    );
    let current = Store::open(alice.paths.clone())
        .unwrap()
        .load_all()
        .unwrap()
        .remove(0);
    let bob_keys = Store::open(bob.paths.clone())
        .unwrap()
        .read_account()
        .unwrap()
        .unlock(PASSWORD.as_bytes())
        .unwrap();
    assert!(
        current
            .grants
            .iter()
            .all(|g| &g.recipient != bob_keys.public_key())
    );
}

#[test]
fn local_only_files_never_upload_and_keep_their_policy_across_edits_lock_and_relogin() {
    let server = Server::start();
    let mut first = Device::start(true);
    let (private, baseline) = add_file(&mut first, "api/private", b"PRIVATE=one\n", true);
    let id = private.id.to_string();
    assert!(private.local_only);
    let (edited, _) = edit_file(&mut first, &id, b"PRIVATE=two\n", &baseline);
    assert!(edited.local_only);
    assert!(!first.paths.vault_dir().join(format!("{id}.json")).exists());
    assert!(
        first
            .paths
            .home()
            .join("local-vault")
            .join(format!("{id}.json"))
            .exists()
    );
    assert!(
        first
            .paths
            .home()
            .join("local-vault/history")
            .join(&id)
            .join("1.json")
            .exists()
    );
    // If an older client rewrites the trust registry, the separate on-disk
    // location still restores the private policy on the next unlock.
    let trust_path = first.paths.home().join("trust.json");
    let mut trust: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&trust_path).unwrap()).unwrap();
    trust.as_object_mut().unwrap().remove("local_only");
    std::fs::write(&trust_path, serde_json::to_vec(&trust).unwrap()).unwrap();

    first.register(&server, "alice");
    add_file(&mut first, "api/shared", b"PUBLIC=one\n", false);
    let report = first.sync();
    assert_eq!(report.pushed, 1);
    let Reply::SyncStatus(Some(status)) = first.call(Request::SyncStatus) else {
        panic!("no status")
    };
    assert_eq!(status.pending, Some(0));
    first.call(Request::Lock);
    first.call(Request::Unlock {
        password: PASSWORD.into(),
        ttl_secs: None,
    });
    assert!(file_snapshot(&mut first, &id).0.local_only);
    first.call(Request::SyncLogout);
    first.login(&server, "alice");
    assert_eq!(first.sync().pushed, 0);
    assert!(file_snapshot(&mut first, &id).0.local_only);
    let mut second = Device::start(false);
    second.login(&server, "alice");
    second.sync();
    assert!(
        second
            .try_call(Request::Get {
                selector: id.clone()
            })
            .is_err()
    );
    let mut bob = Device::start(true);
    bob.register(&server, "bob");
    connect_verified(&mut first, &mut bob);
    assert!(
        first
            .try_call(Request::Share {
                selector: id.clone(),
                username: "bob".into(),
                revoke: false
            })
            .is_err()
    );
    first.call(Request::Remove { selector: id });
    assert_eq!(first.sync().pushed, 0);
}

#[test]
fn file_conflicts_keep_the_server_version_and_all_offline_edits_in_a_private_copy() {
    let server = Server::start();
    let mut first = Device::start(true);
    first.register(&server, "alice");
    let (created, _) = add_file(&mut first, "api/dev", b"A=initial\n", false);
    first.sync();
    let id = created.id.to_string();
    let mut second = Device::start(false);
    second.login(&server, "alice");
    second.sync();
    let (_, version) = file_snapshot(&mut second, &id);
    let (_, version) = edit_file(&mut second, &id, b"A=offline-one\n", &version);
    edit_file(&mut second, &id, b"A=offline-two\n", &version);
    let (_, version) = file_snapshot(&mut first, &id);
    edit_file(&mut first, &id, b"A=server\n", &version);
    first.sync();
    let report = second.sync();
    assert_eq!(report.conflicts.len(), 1);
    assert_eq!(
        report.pushed, 0,
        "conflicting contents must never become current on the server"
    );
    assert_eq!(
        file_bytes(&file_snapshot(&mut second, &id).0),
        b"A=server\n"
    );
    let Reply::List(list) = second.call(Request::List(ListFilter::default())) else {
        panic!("no list")
    };
    let copy = list
        .iter()
        .find(|s| s.local_only)
        .expect("private conflict copy");
    assert_eq!(
        file_bytes(&file_snapshot(&mut second, &copy.id.to_string()).0),
        b"A=offline-two\n"
    );
    let Reply::History(history) = second.call(Request::History {
        selector: copy.id.to_string(),
    }) else {
        panic!("no history")
    };
    assert_eq!(file_bytes(&history[0]), b"A=offline-one\n");
    assert!(history[0].local_only);
    first.sync();
    assert_eq!(file_bytes(&file_snapshot(&mut first, &id).0), b"A=server\n");
    assert_eq!(second.sync().pushed, 0);
}

#[test]
fn owner_deletions_of_shared_files_are_verified_and_propagated() {
    let server = Server::start();
    let mut alice = Device::start(true);
    let mut bob = Device::start(true);
    alice.register(&server, "alice");
    bob.register(&server, "bob");
    connect_verified(&mut alice, &mut bob);
    let (created, _) = add_file(&mut alice, "api/dev", b"A=1\n", false);
    let id = created.id.to_string();
    alice.call(Request::Share {
        selector: id.clone(),
        username: "bob".into(),
        revoke: false,
    });
    bob.sync();
    alice.call(Request::Remove {
        selector: id.clone(),
    });
    alice.sync();
    assert_eq!(bob.sync().removed, 1);
    assert!(bob.try_call(Request::Get { selector: id }).is_err());
}

#[test]
fn deleting_a_file_remotely_keeps_offline_edits_private_instead_of_restoring_it() {
    let server = Server::start();
    let mut first = Device::start(true);
    first.register(&server, "alice");
    let (created, _) = add_file(&mut first, "api/dev", b"A=one\n", false);
    let id = created.id.to_string();
    first.sync();
    let mut second = Device::start(false);
    second.login(&server, "alice");
    second.sync();
    let (_, baseline) = file_snapshot(&mut second, &id);
    edit_file(&mut second, &id, b"A=offline\n", &baseline);
    first.call(Request::Remove {
        selector: id.clone(),
    });
    first.sync();
    let report = second.sync();
    assert_eq!(report.pushed, 0);
    assert_eq!(report.conflicts.len(), 1);
    assert!(
        second
            .try_call(Request::Get {
                selector: id.clone()
            })
            .is_err()
    );
    let Reply::List(list) = second.call(Request::List(ListFilter::default())) else {
        panic!("no list")
    };
    let copy = list.iter().find(|s| s.local_only).unwrap();
    assert_eq!(
        file_bytes(&file_snapshot(&mut second, &copy.id.to_string()).0),
        b"A=offline\n"
    );
    first.sync();
    assert!(first.try_call(Request::Get { selector: id }).is_err());
}

#[test]
fn revocation_publishes_pending_content_after_the_recipient_disconnects() {
    let server = Server::start();
    let mut alice = Device::start(true);
    let mut bob = Device::start(true);
    alice.register(&server, "alice");
    bob.register(&server, "bob");
    connect_verified(&mut alice, &mut bob);
    let (created, _) = add_file(&mut alice, "api/dev", b"A=initial\n", false);
    let id = created.id.to_string();
    alice.call(Request::Share {
        selector: id.clone(),
        username: "bob".into(),
        revoke: false,
    });
    bob.sync();
    bob.call(Request::Disconnect {
        username: "alice".into(),
    });
    let (_, baseline) = file_snapshot(&mut alice, &id);
    let (_, baseline) = edit_file(&mut alice, &id, b"A=pending-one\n", &baseline);
    let (latest, _) = edit_file(&mut alice, &id, b"A=pending-two\n", &baseline);
    assert!(
        !alice.sync().rejected.is_empty(),
        "old grants prevent ordinary sync after disconnection"
    );
    let reply = alice.call(Request::Share {
        selector: id.clone(),
        username: "bob".into(),
        revoke: true,
    });
    let Reply::Shared(revoked) = reply else {
        panic!("revocation did not complete")
    };
    assert_eq!(revoked.revision, latest.revision + 1);
    assert_eq!(
        file_bytes(&file_snapshot(&mut alice, &id).0),
        b"A=pending-two\n"
    );
    let Reply::History(history) = alice.call(Request::History {
        selector: id.clone(),
    }) else {
        panic!("no history")
    };
    assert!(history.iter().any(|v| file_bytes(v) == b"A=pending-one\n"));
    assert!(history.iter().any(|v| file_bytes(v) == b"A=pending-two\n"));
    assert_eq!(
        alice.sync(),
        SyncReport::default(),
        "the actual published revision must be acknowledged, not base + 1"
    );
    let Reply::SyncStatus(Some(status)) = alice.call(Request::SyncStatus) else {
        panic!("no sync status")
    };
    assert_eq!(status.pending, Some(0));
    assert!(status.rejected.is_empty());
    let mut another_owner = Device::start(false);
    another_owner.login(&server, "alice");
    another_owner.sync();
    let (remote, _) = file_snapshot(&mut another_owner, &id);
    assert_eq!(file_bytes(&remote), b"A=pending-two\n");
    assert_eq!(remote.revision, revoked.revision);
    bob.sync();
    assert_eq!(file_bytes(&file_snapshot(&mut bob, &id).0), b"A=initial\n");
    let bob_keys = Store::open(bob.paths.clone())
        .unwrap()
        .read_account()
        .unwrap()
        .unlock(PASSWORD.as_bytes())
        .unwrap();
    let current = Store::open(alice.paths.clone())
        .unwrap()
        .load_all()
        .unwrap()
        .into_iter()
        .find(|s| s.secret.id == created.id)
        .unwrap();
    assert!(
        current
            .grants
            .iter()
            .all(|g| &g.recipient != bob_keys.public_key())
    );
}

#[test]
fn sharing_reports_preparatory_conflicts_and_waits_for_an_explicit_retry() {
    let server = Server::start();
    let mut alice = Device::start(true);
    let mut bob = Device::start(true);
    alice.register(&server, "alice");
    bob.register(&server, "bob");
    connect_verified(&mut alice, &mut bob);
    let (created, _) = add_file(&mut alice, "api/dev", b"A=initial\n", false);
    alice.sync();
    let id = created.id.to_string();
    let mut stale = Device::start(false);
    stale.login(&server, "alice");
    stale.sync();
    stale.call(Request::VerifyPeer {
        username: "bob".into(),
        fingerprint: fingerprint(&bob),
    });
    let (_, version) = file_snapshot(&mut stale, &id);
    edit_file(&mut stale, &id, b"A=offline\n", &version);
    let (_, version) = file_snapshot(&mut alice, &id);
    edit_file(&mut alice, &id, b"A=server\n", &version);
    alice.sync();
    let result = stale.try_call(Request::Share {
        selector: id.clone(),
        username: "bob".into(),
        revoke: false,
    });
    let Err(ClientError::Agent(AgentError::Invalid { message })) = result else {
        panic!("sharing must not silently succeed after a conflict")
    };
    assert!(message.contains("sharing was not applied"));
    assert!(message.contains("kept the server version"));
    let Reply::List(list) = stale.call(Request::List(ListFilter::default())) else {
        panic!("no list")
    };
    let copy = list.iter().find(|s| s.local_only).unwrap();
    assert!(
        message.contains(&copy.id.to_string()),
        "the caller must receive the recovery path even though sync consumed the conflict"
    );
    assert_eq!(
        file_bytes(&file_snapshot(&mut stale, &copy.id.to_string()).0),
        b"A=offline\n"
    );
    bob.sync();
    assert!(
        bob.try_call(Request::Get {
            selector: id.clone()
        })
        .is_err(),
        "sharing must wait for explicit retry after conflict recovery"
    );
    assert!(
        stale.sync().conflicts.is_empty(),
        "the conflict was consumed by preparatory sync"
    );
    stale.call(Request::Share {
        selector: id.clone(),
        username: "bob".into(),
        revoke: false,
    });
    bob.sync();
    assert_eq!(file_bytes(&file_snapshot(&mut bob, &id).0), b"A=server\n");
}

#[test]
fn atomic_revocation_removes_disconnected_recipients_and_retains_connected_ones() {
    let server = Server::start();
    let mut alice = Device::start(true);
    let mut bob = Device::start(true);
    let mut carol = Device::start(true);
    let mut dave = Device::start(true);
    alice.register(&server, "alice");
    bob.register(&server, "bob");
    carol.register(&server, "carol");
    dave.register(&server, "dave");
    for (name, peer) in [
        ("bob", &mut bob),
        ("carol", &mut carol),
        ("dave", &mut dave),
    ] {
        alice.call(Request::Connect {
            username: name.into(),
        });
        peer.call(Request::Connect {
            username: "alice".into(),
        });
        alice.call(Request::VerifyPeer {
            username: name.into(),
            fingerprint: fingerprint(peer),
        });
        peer.call(Request::VerifyPeer {
            username: "alice".into(),
            fingerprint: fingerprint(&alice),
        });
    }
    let (created, _) = add_file(&mut alice, "api/dev", b"A=initial\n", false);
    let id = created.id.to_string();
    alice.call(Request::ShareMany {
        selector: id.clone(),
        usernames: vec!["bob".into(), "carol".into(), "dave".into(), "bob".into()],
        revoke: false,
    });
    for peer in [&mut bob, &mut carol, &mut dave] {
        peer.sync();
        assert_eq!(file_bytes(&file_snapshot(peer, &id).0), b"A=initial\n");
    }
    for peer in [&mut bob, &mut carol] {
        peer.call(Request::Disconnect {
            username: "alice".into(),
        });
    }
    let (_, baseline) = file_snapshot(&mut alice, &id);
    let (_, baseline) = edit_file(&mut alice, &id, b"A=pending-one\n", &baseline);
    let (latest, version) = edit_file(&mut alice, &id, b"A=pending-two\n", &baseline);
    // Each individual change is still rejected while it retains the other
    // disconnected recipient; the batch must remove both atomically.
    for username in ["bob", "carol"] {
        assert!(
            alice
                .try_call(Request::Share {
                    selector: id.clone(),
                    username: username.into(),
                    revoke: true
                })
                .is_err()
        );
    }
    assert!(
        alice
            .try_call(Request::ShareMany {
                selector: id.clone(),
                usernames: vec![],
                revoke: true
            })
            .is_err()
    );
    assert!(
        alice
            .try_call(Request::ShareMany {
                selector: id.clone(),
                usernames: vec!["bob".into(), "unverified".into()],
                revoke: true
            })
            .is_err()
    );
    assert_eq!(
        file_snapshot(&mut alice, &id).1,
        version,
        "failed batches must not partially modify recipient grants or contents"
    );
    let Reply::Shared(revoked) = alice.call(Request::ShareMany {
        selector: id.clone(),
        usernames: vec!["bob".into(), "carol".into(), "bob".into()],
        revoke: true,
    }) else {
        panic!("revocation did not complete")
    };
    assert_eq!(
        revoked.revision,
        latest.revision + 1,
        "the recipient set must change in one revision"
    );
    assert_eq!(
        file_bytes(&file_snapshot(&mut alice, &id).0),
        b"A=pending-two\n"
    );
    let Reply::History(history) = alice.call(Request::History {
        selector: id.clone(),
    }) else {
        panic!("no history")
    };
    assert!(history.iter().any(|v| file_bytes(v) == b"A=pending-one\n"));
    assert!(history.iter().any(|v| file_bytes(v) == b"A=pending-two\n"));
    assert_eq!(alice.sync(), SyncReport::default());
    dave.sync();
    assert_eq!(
        file_bytes(&file_snapshot(&mut dave, &id).0),
        b"A=pending-two\n"
    );
    let current = Store::open(alice.paths.clone())
        .unwrap()
        .load_all()
        .unwrap()
        .into_iter()
        .find(|s| s.secret.id == created.id)
        .unwrap();
    let dave_keys = Store::open(dave.paths.clone())
        .unwrap()
        .read_account()
        .unwrap()
        .unlock(PASSWORD.as_bytes())
        .unwrap();
    let alice_keys = Store::open(alice.paths.clone())
        .unwrap()
        .read_account()
        .unwrap()
        .unlock(PASSWORD.as_bytes())
        .unwrap();
    assert_eq!(current.grants.len(), 2);
    assert!(
        current
            .grants
            .iter()
            .all(|g| &g.recipient == alice_keys.public_key()
                || &g.recipient == dave_keys.public_key())
    );
    for peer in [&mut bob, &mut carol] {
        peer.sync();
        assert_eq!(file_bytes(&file_snapshot(peer, &id).0), b"A=initial\n");
    }
    let (_, baseline) = file_snapshot(&mut alice, &id);
    edit_file(&mut alice, &id, b"A=after-revoke\n", &baseline);
    assert_eq!(
        alice.sync().pushed,
        1,
        "ordinary edits must sync again without reconnecting revoked recipients"
    );
    dave.sync();
    assert_eq!(
        file_bytes(&file_snapshot(&mut dave, &id).0),
        b"A=after-revoke\n"
    );
}

fn recovery_notices_survive_failed_uploads(through_sharing: bool) {
    for remote_deletion in [false, true] {
        let server = Server::start();
        let mut alice = Device::start(true);
        let mut bob = Device::start(true);
        alice.register(&server, "alice");
        bob.register(&server, "bob");
        connect_verified(&mut alice, &mut bob);
        let (created, _) = add_file(&mut alice, "api/dev", b"A=initial\n", false);
        alice.sync();
        let id = created.id.to_string();
        let mut stale = Device::start(false);
        stale.login(&server, "alice");
        stale.sync();
        stale.call(Request::VerifyPeer {
            username: "bob".into(),
            fingerprint: fingerprint(&bob),
        });
        let (_, version) = file_snapshot(&mut stale, &id);
        edit_file(&mut stale, &id, b"A=offline\n", &version);
        stale.add_note("notes/pending", "pending upload");
        if remote_deletion {
            alice.call(Request::Remove {
                selector: id.clone(),
            });
        } else {
            let (_, version) = file_snapshot(&mut alice, &id);
            edit_file(&mut alice, &id, b"A=server\n", &version);
        }
        alice.sync();
        server.fail_pushes.store(true, Ordering::SeqCst);
        let request = if through_sharing {
            Request::Share {
                selector: id.clone(),
                username: "bob".into(),
                revoke: false,
            }
        } else {
            Request::Sync
        };
        let Err(ClientError::Agent(AgentError::Sync { message })) = stale.try_call(request.clone())
        else {
            panic!("expected injected upload failure")
        };
        assert!(message.contains("HTTP 503"));
        let Reply::List(list) = stale.call(Request::List(ListFilter::default())) else {
            panic!("no list")
        };
        let copy = list.iter().find(|s| s.local_only).unwrap();
        let copy_id = copy.id.to_string();
        assert!(
            message.contains(&copy_id),
            "the original failure must include the already-persisted recovery path"
        );
        assert_eq!(
            file_bytes(&file_snapshot(&mut stale, &copy_id).0),
            b"A=offline\n"
        );
        let store = Store::open(stale.paths.clone()).unwrap();
        let queued = store.read_conflict_notices().unwrap();
        assert_eq!(queued.len(), 1);
        assert!(queued[0].contains(&copy_id));
        assert!(
            !std::fs::read_to_string(stale.paths.home().join("conflict-notices.json"))
                .unwrap()
                .contains("A=offline")
        );
        stale.restart();
        let Err(ClientError::Agent(AgentError::Sync { message })) = stale.try_call(request.clone())
        else {
            panic!("expected repeated upload failure")
        };
        assert!(message.contains("HTTP 503") && message.contains(&copy_id));
        assert_eq!(
            store.read_conflict_notices().unwrap(),
            queued,
            "failed retries must not duplicate or consume notices"
        );
        stale.call(Request::SyncLogout);
        stale.login(&server, "alice");
        assert_eq!(store.read_conflict_notices().unwrap(), queued);
        server.fail_pushes.store(false, Ordering::SeqCst);
        if through_sharing {
            let Err(ClientError::Agent(AgentError::Invalid { message })) =
                stale.try_call(request.clone())
            else {
                panic!("sharing must surface the recovered notice before publishing")
            };
            assert!(message.contains("sharing was not applied") && message.contains(&copy_id));
            bob.sync();
            assert!(
                bob.try_call(Request::Get {
                    selector: id.clone()
                })
                .is_err()
            );
            if !remote_deletion {
                stale.call(request);
                bob.sync();
                assert_eq!(file_bytes(&file_snapshot(&mut bob, &id).0), b"A=server\n");
            }
        } else {
            let report = stale.sync();
            assert_eq!(
                report.conflicts, queued,
                "the first successful retry must deliver the durable notice"
            );
        }
        stale.call(Request::SyncStatus);
        assert!(store.read_conflict_notices().unwrap().is_empty());
        assert_eq!(stale.sync(), SyncReport::default());
        alice.sync();
        assert_eq!(
            alice.text("notes/pending").as_deref(),
            Some("pending upload")
        );
        let Reply::List(list) = stale.call(Request::List(ListFilter::default())) else {
            panic!("no list")
        };
        assert_eq!(list.iter().filter(|s| s.local_only).count(), 1);
    }
}

#[test]
fn conflict_notices_survive_failed_uploads_restart_and_relogin() {
    recovery_notices_survive_failed_uploads(false);
}

#[test]
fn sharing_preserves_recovery_notices_after_later_upload_failures() {
    recovery_notices_survive_failed_uploads(true);
}

#[test]
fn file_conflict_notice_is_durable_before_history_cleanup() {
    let server = Server::start();
    let mut alice = Device::start(true);
    alice.register(&server, "alice");
    let (created, _) = add_file(&mut alice, "api/dev", b"A=initial\n", false);
    alice.sync();
    let id = created.id.to_string();
    let mut stale = Device::start(false);
    stale.login(&server, "alice");
    stale.sync();
    let (_, version) = file_snapshot(&mut stale, &id);
    let (_, version) = edit_file(&mut stale, &id, b"A=offline-one\n", &version);
    let (latest, _) = edit_file(&mut stale, &id, b"A=offline-two\n", &version);
    let (_, version) = file_snapshot(&mut alice, &id);
    edit_file(&mut alice, &id, b"A=server\n", &version);
    alice.sync();
    // This current revision has no history file yet; an unexpected directory
    // at that path makes cleanup fail after the preceding revision is removed.
    let obstacle = stale
        .paths
        .vault_dir()
        .join("history")
        .join(&id)
        .join(format!("{}.json", latest.revision));
    std::fs::create_dir(&obstacle).unwrap();
    let Err(ClientError::Agent(AgentError::Sync { message })) = stale.try_call(Request::Sync)
    else {
        panic!("expected cleanup failure")
    };
    let store = Store::open(stale.paths.clone()).unwrap();
    let notices = store.read_conflict_notices().unwrap();
    assert_eq!(notices.len(), 1);
    let Reply::List(list) = stale.call(Request::List(ListFilter::default())) else {
        panic!("no list")
    };
    let copy = list.iter().find(|s| s.local_only).unwrap();
    assert!(message.contains(&copy.id.to_string()) && notices[0].contains(&copy.id.to_string()));
    let Reply::History(history) = stale.call(Request::History {
        selector: copy.id.to_string(),
    }) else {
        panic!("no history")
    };
    assert_eq!(file_bytes(&history[0]), b"A=offline-one\n");
    assert_eq!(
        file_bytes(&file_snapshot(&mut stale, &copy.id.to_string()).0),
        b"A=offline-two\n"
    );
    std::fs::remove_dir(obstacle).unwrap();
    let report = stale.sync();
    assert!(
        report
            .conflicts
            .iter()
            .any(|notice| notice.contains(&copy.id.to_string()))
    );
    assert_eq!(file_bytes(&file_snapshot(&mut stale, &id).0), b"A=server\n");
    assert!(store.read_conflict_notices().unwrap().is_empty());
}

#[test]
fn canceled_sync_and_sharing_responses_leave_recovery_notices_for_retry() {
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    for through_sharing in [false, true] {
        let server = Server::start();
        let mut alice = Device::start(true);
        let mut bob = Device::start(true);
        alice.register(&server, "alice");
        bob.register(&server, "bob");
        connect_verified(&mut alice, &mut bob);
        let (created, _) = add_file(&mut alice, "api/dev", b"A=initial\n", false);
        alice.sync();
        let id = created.id.to_string();
        let mut stale = Device::start(false);
        stale.login(&server, "alice");
        stale.sync();
        stale.call(Request::VerifyPeer {
            username: "bob".into(),
            fingerprint: fingerprint(&bob),
        });
        let (_, baseline) = file_snapshot(&mut stale, &id);
        edit_file(&mut stale, &id, b"A=offline\n", &baseline);
        let (_, baseline) = file_snapshot(&mut alice, &id);
        edit_file(&mut alice, &id, b"A=server\n", &baseline);
        alice.sync();
        let request = if through_sharing {
            Request::Share {
                selector: id.clone(),
                username: "bob".into(),
                revoke: false,
            }
        } else {
            Request::Sync
        };
        let mut canceled = UnixStream::connect(stale.paths.socket_file()).unwrap();
        let mut message = serde_json::to_vec(&request).unwrap();
        message.push(b'\n');
        canceled.write_all(&message).unwrap();
        canceled.shutdown(Shutdown::Both).unwrap();
        drop(canceled);
        // Wait until the canceled request has actually performed recovery;
        // list/status reads do not synchronize or consume notices.
        let copy = (0..200)
            .find_map(|_| {
                let Reply::List(list) = stale.call(Request::List(ListFilter::default())) else {
                    panic!("no list")
                };
                let copy = list.into_iter().find(|s| s.local_only);
                if copy.is_none() {
                    thread::sleep(Duration::from_millis(10));
                }
                copy
            })
            .expect("canceled request recovered its file conflict");
        let copy_id = copy.id.to_string();
        assert_eq!(
            file_bytes(&file_snapshot(&mut stale, &copy_id).0),
            b"A=offline\n"
        );
        assert_eq!(file_bytes(&file_snapshot(&mut stale, &id).0), b"A=server\n");
        let report = stale.sync();
        assert_eq!(
            report.conflicts.len(),
            1,
            "an undelivered response must not acknowledge the recovery path"
        );
        assert!(report.conflicts[0].contains(&copy_id));
        assert!(
            Store::open(stale.paths.clone())
                .unwrap()
                .read_conflict_notices()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            stale.sync(),
            SyncReport::default(),
            "a successfully delivered report is acknowledged"
        );
        if through_sharing {
            bob.sync();
            assert!(
                bob.try_call(Request::Get { selector: id }).is_err(),
                "cancellation must not turn conflict recovery into an implicit sharing retry"
            );
        }
    }
}
