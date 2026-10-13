//! End-to-end tests of the HTTP API against an in-memory database.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use silo_core::account::{AccountKeys, AccountRecord};
use silo_core::crypto::{AuthKey, KdfParams, PublicKey};
use silo_core::sync::{
    self, Change, ChangesReply, ConnectionsReply, PushItem, PushReply, PushResult, SessionReply,
    Tombstone,
};
use silo_core::vault::{
    FolderPath, Grant, Note, SealedSecret, SecretBody, SecretId, SecretKind, SecretMeta,
    StoredSecret,
};
use tower::ServiceExt;

use crate::{AppState, Db, accounts, app};

struct Server {
    app: Router,
    db: Db,
    key: PublicKey,
}

struct User {
    keys: AccountKeys,
    auth: [u8; 32],
    token: String,
}

impl Server {
    fn new() -> Self {
        let db = Db::open_in_memory().unwrap();
        Self {
            app: app(AppState::new(db.clone()).unwrap()),
            key: db.server_key().unwrap().public_key(),
            db,
        }
    }

    fn invite(&self) -> String {
        self.db
            .with(|conn| accounts::create_invite(conn, &mut rand::rng(), crate::unix_now(), 7))
            .unwrap()
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let request = match body {
            Some(body) => request
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    fn register_body(
        &self,
        name: &str,
        keys: &AccountKeys,
        record: &AccountRecord,
        auth: [u8; 32],
        invite: &str,
    ) -> Value {
        json!({
            "invite": invite,
            "username": name,
            "account": record,
            "identity": keys.identity(),
            "proof": sync::prove_registration(keys, name, &self.key).unwrap(),
            "auth_key": AuthKey::from_bytes(auth),
            "device_name": "laptop",
        })
    }

    async fn register(&self, name: &str) -> User {
        let (record, keys) = new_account();
        let auth = [name.len() as u8; 32];
        let body = self.register_body(name, &keys, &record, auth, &self.invite());
        let (status, reply) = self.call("POST", "/v1/register", None, Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        let session: SessionReply = serde_json::from_value(reply).unwrap();
        assert_eq!(session.account.username, name);
        assert_eq!(session.account.identity, keys.identity());
        User {
            keys,
            auth,
            token: session.token,
        }
    }

    async fn push(&self, user: &User, items: Vec<PushItem>) -> Vec<PushResult> {
        let body = serde_json::to_value(sync::PushRequest { items }).unwrap();
        let (status, reply) = self
            .call("POST", "/v1/push", Some(&user.token), Some(body))
            .await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        serde_json::from_value::<PushReply>(reply).unwrap().results
    }

    async fn changes(&self, user: &User, since: u64) -> ChangesReply {
        let (status, reply) = self
            .call(
                "GET",
                &format!("/v1/changes?since={since}"),
                Some(&user.token),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        serde_json::from_value(reply).unwrap()
    }
}

fn entry(
    author: &AccountKeys,
    id: SecretId,
    revision: u32,
    text: &str,
    recipients: &[PublicKey],
) -> StoredSecret {
    let mut rng = rand::rng();
    let meta = SecretMeta {
        title: "note".into(),
        kind: SecretKind::Note,
        folder: FolderPath::root(),
        tags: vec![],
        urls: vec![],
        created_at: 0,
        updated_at: 0,
    };
    let body = SecretBody::Note(Note { text: text.into() });
    let (secret, key) = SealedSecret::seal(&mut rng, author, id, revision, &meta, &body).unwrap();
    let grants = recipients
        .iter()
        .map(|r| Grant::seal(&mut rng, author, &secret, &key, *r).unwrap())
        .collect();
    StoredSecret { secret, grants }
}

fn new_account() -> (AccountRecord, AccountKeys) {
    let mut rng = rand::rng();
    let kdf = KdfParams::recommended(&mut rng);
    AccountRecord::create(&mut rng, b"pw", kdf).unwrap()
}

fn new_weak_account() -> (AccountRecord, AccountKeys) {
    let mut rng = rand::rng();
    let kdf = KdfParams::new(&mut rng, 256, 1, 1);
    AccountRecord::create(&mut rng, b"pw", kdf).unwrap()
}

fn put(base_revision: u32, entry: StoredSecret) -> PushItem {
    PushItem::Put {
        base_revision,
        entry,
        restore: false,
    }
}

fn restore(base_revision: u32, entry: StoredSecret) -> PushItem {
    PushItem::Put {
        base_revision,
        entry,
        restore: true,
    }
}

fn new_id(byte: u8) -> SecretId {
    SecretId::from_random_bytes([byte; 16])
}

fn conflict(result: &PushResult) -> &Change {
    match result {
        PushResult::Conflict { current } => current,
        other => panic!("expected a conflict, got {other:?}"),
    }
}

fn rejected(result: &PushResult) -> &str {
    match result {
        PushResult::Rejected { message } => message,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn health_and_prelogin_hide_which_accounts_exist() {
    let server = Server::new();
    let (status, health) = server.call("GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(health["status"], "ok");

    let alice = server.register("alice").await;
    let (_, real) = server.call("GET", "/v1/prelogin/Alice", None, None).await;
    let (_, ghost) = server.call("GET", "/v1/prelogin/ghost", None, None).await;
    let (_, ghost_again) = server.call("GET", "/v1/prelogin/ghost", None, None).await;
    let (_, other_ghost) = server.call("GET", "/v1/prelogin/casper", None, None).await;

    let record: AccountRecord = serde_json::from_value(
        server
            .call("GET", "/v1/account", Some(&alice.token), None)
            .await
            .1["account"]
            .clone(),
    )
    .unwrap();
    assert_eq!(real["kdf"], serde_json::to_value(&record.kdf).unwrap());
    assert_eq!(ghost, ghost_again);
    assert_ne!(ghost["kdf"]["salt"], other_ghost["kdf"]["salt"]);
    // Same shape as a real one, and acceptable to a client.
    let made_up: sync::PreloginReply = serde_json::from_value(ghost).unwrap();
    assert!(made_up.kdf.check_minimum().is_ok());

    let (status, _) = server
        .call("GET", "/v1/prelogin/no%20spaces", None, None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn registration_needs_a_fresh_invite_and_your_own_keys() {
    let server = Server::new();
    let (record, keys) = new_account();
    let invite = server.invite();

    let (status, reply) = server
        .call(
            "POST",
            "/v1/register",
            None,
            Some(server.register_body("bob", &keys, &record, [1; 32], "nope")),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(reply["error"]["code"], "invite_invalid");

    // A proof signed for another name does not count.
    let mut body = server.register_body("bob", &keys, &record, [1; 32], &invite);
    body["proof"] =
        serde_json::to_value(sync::prove_registration(&keys, "rob", &server.key).unwrap()).unwrap();
    let (status, reply) = server.call("POST", "/v1/register", None, Some(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");

    // Weak password hashing is refused, so prelogin never hands it out, and
    // so is stronger hashing: prelogin would tell those accounts apart.
    let (weak_record, weak_keys) = new_weak_account();
    let mut stronger = record.clone();
    stronger.kdf.memory_kib *= 2;
    let (status, reply) = server
        .call(
            "POST",
            "/v1/register",
            None,
            Some(server.register_body("strong", &keys, &stronger, [1; 32], &invite)),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("recommended")
    );
    let (status, reply) = server
        .call(
            "POST",
            "/v1/register",
            None,
            Some(server.register_body("weak", &weak_keys, &weak_record, [1; 32], &invite)),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");

    let (status, _) = server
        .call(
            "POST",
            "/v1/register",
            None,
            Some(server.register_body("bob", &keys, &record, [1; 32], &invite)),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // The invite is spent.
    let (status, _) = server
        .call(
            "POST",
            "/v1/register",
            None,
            Some(server.register_body("bob2", &keys, &record, [1; 32], &invite)),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, reply) = server
        .call(
            "POST",
            "/v1/register",
            None,
            Some(server.register_body("BOB", &weak_keys, &record, [1; 32], &server.invite())),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "mismatched record and identity: {reply}"
    );

    let (other_record, other_keys) = new_account();
    let (status, reply) = server
        .call(
            "POST",
            "/v1/register",
            None,
            Some(server.register_body(
                "bob",
                &other_keys,
                &other_record,
                [1; 32],
                &server.invite(),
            )),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reply["error"]["code"], "username_taken");

    let (status, reply) = server
        .call(
            "POST",
            "/v1/register",
            None,
            Some(server.register_body("robert", &keys, &record, [1; 32], &server.invite())),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reply["error"]["code"], "identity_taken");
}

#[tokio::test]
async fn login_devices_and_logout() {
    let server = Server::new();
    let alice = server.register("alice").await;
    let login = |auth: [u8; 32], name: &str| json!({ "username": "ALICE", "auth_key": AuthKey::from_bytes(auth), "device_name": name });

    let (status, reply) = server
        .call("POST", "/v1/login", None, Some(login([9; 32], "x")))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply["error"]["code"], "unauthorized");
    let (status, _) = server
        .call("POST", "/v1/login", None, Some(json!({ "username": "nobody", "auth_key": AuthKey::from_bytes([1; 32]), "device_name": "x" })))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, reply) = server
        .call(
            "POST",
            "/v1/login",
            None,
            Some(login(alice.auth, "desktop")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let desktop: SessionReply = serde_json::from_value(reply).unwrap();
    assert_ne!(desktop.token, alice.token);

    let (_, reply) = server
        .call("GET", "/v1/devices", Some(&desktop.token), None)
        .await;
    let devices = reply["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 2);
    let laptop = devices.iter().find(|d| d["name"] == "laptop").unwrap();
    assert_eq!(laptop["current"], false);
    assert!(
        devices
            .iter()
            .any(|d| d["name"] == "desktop" && d["current"] == true)
    );

    // Revoking the laptop from the desktop locks the laptop out.
    let path = format!("/v1/devices/{}", laptop["id"].as_str().unwrap());
    let (status, _) = server
        .call("DELETE", &path, Some(&desktop.token), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = server
        .call("GET", "/v1/account", Some(&alice.token), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server
        .call("DELETE", &path, Some(&desktop.token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = server
        .call("POST", "/v1/logout", Some(&desktop.token), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = server
        .call("GET", "/v1/devices", Some(&desktop.token), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server.call("GET", "/v1/devices", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn repeated_wrong_logins_are_slowed_down() {
    let server = Server::new();
    let alice = server.register("alice").await;
    let body = |auth: [u8; 32]| json!({ "username": "alice", "auth_key": AuthKey::from_bytes(auth), "device_name": "x" });
    for _ in 0..5 {
        let (status, _) = server
            .call("POST", "/v1/login", None, Some(body([0; 32])))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, reply) = server
        .call("POST", "/v1/login", None, Some(body(alice.auth)))
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(reply["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn push_pull_conflict_delete_and_restore() {
    let server = Server::new();
    let alice = server.register("alice").await;
    let me = *alice.keys.public_key();
    let id = new_id(1);

    // A new secret, then an edit on top of it.
    let results = server
        .push(
            &alice,
            vec![put(0, entry(&alice.keys, id, 1, "one", &[me]))],
        )
        .await;
    assert!(matches!(results[0], PushResult::Ok { seq: 1 }));
    let results = server
        .push(
            &alice,
            vec![put(1, entry(&alice.keys, id, 2, "two", &[me]))],
        )
        .await;
    assert!(matches!(results[0], PushResult::Ok { seq: 2 }));

    let pulled = server.changes(&alice, 0).await;
    assert_eq!(pulled.cursor, 2);
    assert!(!pulled.more);
    assert_eq!(pulled.account_version, 1);
    let [
        Change::Put {
            seq: 2,
            entry: current,
        },
    ] = pulled.changes.as_slice()
    else {
        panic!("{:?}", pulled.changes)
    };
    assert_eq!(current.secret.revision, 2);
    assert_eq!(current.verify(&alice.keys.identity().signing_key), Ok(()));
    let key = current.grants[0].open(&alice.keys).unwrap();
    assert_eq!(
        current.secret.open_body(&key).unwrap(),
        SecretBody::Note(Note { text: "two".into() })
    );
    assert!(server.changes(&alice, 2).await.changes.is_empty());

    // Another device edited revision 1 meanwhile: conflict, with what the server holds.
    let results = server
        .push(
            &alice,
            vec![put(1, entry(&alice.keys, id, 2, "stale", &[me]))],
        )
        .await;
    let Change::Put { entry: theirs, .. } = conflict(&results[0]) else {
        panic!("{results:?}")
    };
    assert_eq!(theirs.secret.revision, 2);
    assert_eq!(
        rejected(
            &server
                .push(
                    &alice,
                    vec![put(2, entry(&alice.keys, id, 2, "same", &[me]))]
                )
                .await[0]
        ),
        "the new revision must be newer than its base"
    );

    // Delete, sent twice; the second is a no-op.
    let tombstone = Tombstone::seal(&alice.keys, id, 2, 100);
    let results = server
        .push(
            &alice,
            vec![
                PushItem::Delete {
                    tombstone: tombstone.clone(),
                },
                PushItem::Delete {
                    tombstone: tombstone.clone(),
                },
            ],
        )
        .await;
    assert_eq!(results[0], PushResult::Ok { seq: 3 });
    assert_eq!(results[1], PushResult::Ok { seq: 3 });
    let pulled = server.changes(&alice, 2).await;
    assert_eq!(pulled.changes, vec![Change::Delete { seq: 3, tombstone }]);

    // A delete of an older revision conflicts.
    let results = server
        .push(
            &alice,
            vec![PushItem::Delete {
                tombstone: Tombstone::seal(&alice.keys, id, 1, 100),
            }],
        )
        .await;
    assert!(matches!(conflict(&results[0]), Change::Delete { .. }));

    // An edit made before the delete conflicts, whether its base is older or
    // the deleted revision itself: it never saw the deletion.
    let results = server
        .push(
            &alice,
            vec![put(1, entry(&alice.keys, id, 3, "late", &[me]))],
        )
        .await;
    assert!(matches!(conflict(&results[0]), Change::Delete { .. }));
    let results = server
        .push(
            &alice,
            vec![put(2, entry(&alice.keys, id, 3, "offline", &[me]))],
        )
        .await;
    assert!(matches!(conflict(&results[0]), Change::Delete { .. }));
    // Only an explicit restore brings it back.
    let results = server
        .push(
            &alice,
            vec![restore(2, entry(&alice.keys, id, 3, "back", &[me]))],
        )
        .await;
    assert_eq!(results[0], PushResult::Ok { seq: 4 });
    let pulled = server.changes(&alice, 3).await;
    assert!(matches!(&pulled.changes[..], [Change::Put { seq: 4, .. }]));
    // And a restore of something no longer deleted conflicts.
    let results = server
        .push(
            &alice,
            vec![restore(3, entry(&alice.keys, id, 4, "again", &[me]))],
        )
        .await;
    assert!(matches!(conflict(&results[0]), Change::Put { .. }));
}

#[tokio::test]
async fn an_offline_edit_does_not_undo_a_deletion() {
    // The reproduction from review: revision 1, an edit prepared on top of
    // it elsewhere, then revision 1 deleted, then the edit pushed.
    let server = Server::new();
    let alice = server.register("alice").await;
    let me = *alice.keys.public_key();
    let id = new_id(20);
    server
        .push(
            &alice,
            vec![put(0, entry(&alice.keys, id, 1, "one", &[me]))],
        )
        .await;
    let offline = entry(&alice.keys, id, 2, "two", &[me]);
    let tombstone = Tombstone::seal(&alice.keys, id, 1, 50);
    let results = server
        .push(
            &alice,
            vec![PushItem::Delete {
                tombstone: tombstone.clone(),
            }],
        )
        .await;
    assert_eq!(results[0], PushResult::Ok { seq: 2 });

    let results = server.push(&alice, vec![put(1, offline)]).await;
    assert_eq!(conflict(&results[0]), &Change::Delete { seq: 2, tombstone });
    assert!(server.changes(&alice, 2).await.changes.is_empty());
}

#[tokio::test]
async fn registration_cannot_claim_someone_elses_encryption_key() {
    // The reproduction from review: Mallory copies Alice's public account
    // record and pairs its X25519 key with her own signing key.
    let server = Server::new();
    let (alice_record, alice_keys) = new_account();
    let (_, mallory_keys) = new_account();

    let (status, info) = server.call("GET", "/v1/server", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        info["public_key"],
        serde_json::to_value(server.key).unwrap()
    );

    let claimed = silo_core::account::Identity {
        public_key: *alice_keys.public_key(),
        signing_key: mallory_keys.identity().signing_key,
    };
    // Whatever she signs, she cannot make the key proof without Alice's
    // secret key. (A signature that does verify over the claimed identity is
    // covered in silo-core's `registration_proof_needs_both_secret_keys`.)
    let proof = sync::prove_registration(&mallory_keys, "mallory", &server.key).unwrap();
    let mut body = server.register_body(
        "mallory",
        &mallory_keys,
        &alice_record,
        [2; 32],
        &server.invite(),
    );
    body["identity"] = serde_json::to_value(claimed).unwrap();
    body["proof"] = serde_json::to_value(proof).unwrap();
    let (status, reply) = server.call("POST", "/v1/register", None, Some(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");

    // Alice can still register her real identity.
    let body = server.register_body(
        "alice",
        &alice_keys,
        &alice_record,
        [1; 32],
        &server.invite(),
    );
    let (status, reply) = server.call("POST", "/v1/register", None, Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
}

#[tokio::test]
async fn forged_and_foreign_pushes_are_rejected() {
    let server = Server::new();
    let alice = server.register("alice").await;
    let mallory = server.register("mallory").await;
    let a = *alice.keys.public_key();
    let m = *mallory.keys.public_key();
    let id = new_id(2);
    server
        .push(
            &alice,
            vec![put(0, entry(&alice.keys, id, 1, "mine", &[a]))],
        )
        .await;

    // Mallory signs with her own key: not hers to change, and not sent as Alice.
    let results = server
        .push(
            &mallory,
            vec![put(1, entry(&mallory.keys, id, 2, "evil", &[m]))],
        )
        .await;
    assert_eq!(
        rejected(&results[0]),
        "this secret belongs to another account"
    );
    let results = server
        .push(
            &mallory,
            vec![PushItem::Delete {
                tombstone: Tombstone::seal(&mallory.keys, id, 1, 0),
            }],
        )
        .await;
    assert_eq!(
        rejected(&results[0]),
        "this secret belongs to another account"
    );
    // Pushing something signed by Alice from Mallory's device fails the signature check.
    let results = server
        .push(
            &mallory,
            vec![put(1, entry(&alice.keys, id, 2, "replay", &[a]))],
        )
        .await;
    assert_eq!(
        rejected(&results[0]),
        "the revision or a grant is not signed by this account"
    );

    let mut unsigned = entry(&alice.keys, new_id(3), 1, "x", &[a]);
    unsigned.secret.signature = None;
    let results = server.push(&alice, vec![put(0, unsigned)]).await;
    assert_eq!(
        rejected(&results[0]),
        "the revision or a grant is not signed by this account"
    );

    let results = server
        .push(
            &alice,
            vec![put(0, entry(&alice.keys, new_id(4), 1, "x", &[]))],
        )
        .await;
    assert_eq!(rejected(&results[0]), "the owner has no grant of their own");
    let results = server
        .push(
            &alice,
            vec![put(0, entry(&alice.keys, new_id(5), 1, "x", &[a, a]))],
        )
        .await;
    assert_eq!(rejected(&results[0]), "two grants for the same recipient");
    let results = server
        .push(
            &alice,
            vec![put(0, entry(&alice.keys, new_id(6), 1, "x", &[a, m]))],
        )
        .await;
    assert_eq!(
        rejected(&results[0]),
        "a grant goes to an account you are not connected with"
    );

    // Mallory sees none of it.
    let pulled = server.changes(&mallory, 0).await;
    assert!(pulled.changes.is_empty());
    assert_eq!(server.changes(&alice, 0).await.changes.len(), 1);
}

#[tokio::test]
async fn connections_are_mutual_and_gate_sharing() {
    let server = Server::new();
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let connections = |user: &User| {
        let token = user.token.clone();
        let server = &server;
        async move {
            let (status, reply) = server
                .call("GET", "/v1/connections", Some(&token), None)
                .await;
            assert_eq!(status, StatusCode::OK);
            serde_json::from_value::<ConnectionsReply>(reply)
                .unwrap()
                .connections
        }
    };

    let (status, _) = server
        .call("PUT", "/v1/connections/alice", Some(&alice.token), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = server
        .call("PUT", "/v1/connections/nobody", Some(&alice.token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, reply) = server
        .call("PUT", "/v1/connections/bob", Some(&alice.token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["state"], "outgoing");
    assert!(reply.get("identity").is_none());
    // Asking twice changes nothing.
    let (_, reply) = server
        .call("PUT", "/v1/connections/bob", Some(&alice.token), None)
        .await;
    assert_eq!(reply["state"], "outgoing");
    let incoming = connections(&bob).await;
    assert_eq!(incoming[0].username, "alice");
    assert_eq!(incoming[0].state, sync::ConnectionState::Incoming);
    assert_eq!(incoming[0].identity, None);

    // Not connected yet: no sharing.
    let id = new_id(7);
    let a = *alice.keys.public_key();
    let b = *bob.keys.public_key();
    let results = server
        .push(
            &alice,
            vec![put(0, entry(&alice.keys, id, 1, "shared", &[a, b]))],
        )
        .await;
    assert_eq!(
        rejected(&results[0]),
        "a grant goes to an account you are not connected with"
    );

    let (_, reply) = server
        .call("PUT", "/v1/connections/ALICE", Some(&bob.token), None)
        .await;
    assert_eq!(reply["state"], "connected");
    let seen_by_alice = connections(&alice).await;
    assert_eq!(seen_by_alice[0].state, sync::ConnectionState::Connected);
    assert_eq!(seen_by_alice[0].identity, Some(bob.keys.identity()));

    // Connected: Alice shares, Bob pulls it with only his own grant.
    let results = server
        .push(
            &alice,
            vec![put(0, entry(&alice.keys, id, 1, "shared", &[a, b]))],
        )
        .await;
    assert!(matches!(results[0], PushResult::Ok { .. }));
    let pulled = server.changes(&bob, 0).await;
    let [Change::Put { entry: shared, .. }] = pulled.changes.as_slice() else {
        panic!("{:?}", pulled.changes)
    };
    assert_eq!(shared.grants.len(), 1);
    assert_eq!(shared.grants[0].recipient, b);
    assert_eq!(shared.verify(&alice.keys.identity().signing_key), Ok(()));
    let key = shared.grants[0].open(&bob.keys).unwrap();
    assert_eq!(
        shared.secret.open_body(&key).unwrap(),
        SecretBody::Note(Note {
            text: "shared".into()
        })
    );
    // Alice still sees both grants.
    let Change::Put { entry: own, .. } = &server.changes(&alice, 0).await.changes[0] else {
        panic!()
    };
    assert_eq!(own.grants.len(), 2);
    // Bob cannot edit it.
    let results = server
        .push(
            &bob,
            vec![put(1, entry(&bob.keys, id, 2, "bob was here", &[b]))],
        )
        .await;
    assert_eq!(
        rejected(&results[0]),
        "this secret belongs to another account"
    );

    // After disconnecting, new grants to Bob are refused.
    let (status, _) = server
        .call("DELETE", "/v1/connections/bob", Some(&alice.token), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(connections(&bob).await.is_empty());
    let results = server
        .push(
            &alice,
            vec![put(1, entry(&alice.keys, id, 2, "again", &[a, b]))],
        )
        .await;
    assert_eq!(
        rejected(&results[0]),
        "a grant goes to an account you are not connected with"
    );
    let (status, _) = server
        .call("DELETE", "/v1/connections/bob", Some(&alice.token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn changes_come_in_pages_and_reveal_a_lost_server() {
    let server = Server::new();
    let alice = server.register("alice").await;
    let me = *alice.keys.public_key();
    let items = (0..5)
        .map(|i| put(0, entry(&alice.keys, new_id(10 + i), 1, "x", &[me])))
        .collect();
    server.push(&alice, items).await;

    let (_, reply) = server
        .call(
            "GET",
            "/v1/changes?since=0&limit=2",
            Some(&alice.token),
            None,
        )
        .await;
    let page: ChangesReply = serde_json::from_value(reply).unwrap();
    assert_eq!((page.changes.len(), page.cursor, page.more), (2, 2, true));
    let (_, reply) = server
        .call(
            "GET",
            "/v1/changes?since=4&limit=2",
            Some(&alice.token),
            None,
        )
        .await;
    let page: ChangesReply = serde_json::from_value(reply).unwrap();
    assert_eq!((page.changes.len(), page.cursor, page.more), (1, 5, false));

    // A client whose cursor is past anything the server has gets a smaller cursor back.
    let pulled = server.changes(&alice, 50).await;
    assert!(pulled.changes.is_empty());
    assert_eq!(pulled.cursor, 5);

    // Other accounts' pushes move the cursor past them without showing them.
    let bob = server.register("bob").await;
    server
        .push(
            &bob,
            vec![put(
                0,
                entry(&bob.keys, new_id(30), 1, "x", &[*bob.keys.public_key()]),
            )],
        )
        .await;
    let pulled = server.changes(&alice, 5).await;
    assert!(pulled.changes.is_empty());
    assert_eq!(pulled.cursor, 6);
}

#[tokio::test]
async fn malformed_bodies_get_json_errors() {
    let server = Server::new();
    let alice = server.register("alice").await;
    let (status, reply) = server
        .call(
            "POST",
            "/v1/push",
            Some(&alice.token),
            Some(json!({ "items": [{ "op": "explode" }] })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reply["error"]["code"], "invalid");
}
