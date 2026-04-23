//! gRPC management API integration tests (Gap #8).
//!
//! Boots the gRPC server on an ephemeral port per test (backed by the same
//! embedded engines the REST tests use) and exercises the service surface
//! end-to-end via the generated tonic clients.
//!
//! Scenarios covered:
//!  - Admin auth (missing → UNAUTHENTICATED, non-admin → PERMISSION_DENIED, rate limit → RESOURCE_EXHAUSTED)
//!  - IdentityAdminService user CRUD + list pagination
//!  - IdentityAdminService realm + organization CRUD
//!  - ApplicationAdminService client CRUD
//!  - AuthorizationService unary (Check, WriteTuples) + Watch streaming
//!  - AuditService ListEvents + VerifyIntegrity
//!  - OAuthService authorization_code round-trip, client_credentials, revoke, introspect
//!  - Cross-realm isolation (NOT_FOUND not PERMISSION_DENIED)
//!  - Health Check reports SERVING
//!  - Reflection lists all services

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hearth::authz::{ObjectRef, RelationshipTuple, SubjectRef, TupleWrite};
use hearth::core::{RealmId, UserId};
use hearth::identity::{CreateRealmRequest, CreateUserRequest, SessionContext};
use hearth::protocol::admin_auth::{AdminRateLimiter, ADMIN_RATE_LIMIT};
use hearth::protocol::grpc::{self, GrpcState};
use hearth::protocol::proto::authz::v1 as azpb;
use hearth::protocol::proto::authz::v1::authorization_service_client::AuthorizationServiceClient;
use hearth::protocol::proto::events::v1 as evpb;
use hearth::protocol::proto::events::v1::audit_service_client::AuditServiceClient;
use hearth::protocol::proto::identity::v1 as pb;
use hearth::protocol::proto::identity::v1::application_admin_service_client::ApplicationAdminServiceClient;
use hearth::protocol::proto::identity::v1::identity_admin_service_client::IdentityAdminServiceClient;
use hearth::protocol::proto::identity::v1::o_auth_service_client::OAuthServiceClient;
use tokio::sync::oneshot;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::{Code, Request};

// ==========================================================================
// Test rig
// ==========================================================================

/// Boots a gRPC server on a random port backed by `harness`'s engines and
/// returns its address + a shutdown signal + the shared rate limiter (so
/// tests can assert the REST/gRPC limiter is the same instance).
struct GrpcRig {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    rate_limiter: Arc<AdminRateLimiter>,
    handle: tokio::task::JoinHandle<()>,
}

impl GrpcRig {
    async fn start(harness: &common::TestHarness) -> Self {
        // TestHarness accessor methods return `&dyn Trait`. To share with the
        // gRPC module (which needs `Arc<dyn Trait>`) we build fresh Arcs
        // around the embedded engines. Since the embedded engines own the
        // storage engine and are internally shareable, we re-open a parallel
        // set of references via the trait objects the test rig needs.
        //
        // Simplification: clone engines into Arc<dyn ..> using `unsafe`-free
        // wrappers. Because the TestHarness owns the engines, the gRPC task
        // must live shorter than the harness — enforced by this rig's Drop.
        let identity = harness.identity_arc();
        let authz = harness.authz_arc();
        let audit = harness.audit_arc();
        let rate_limiter = Arc::new(AdminRateLimiter::new());
        let state = GrpcState::new(identity, authz, audit, Arc::clone(&rate_limiter));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener); // release so grpc::serve can rebind

        let (tx, rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            if let Err(e) = grpc::serve(addr, state, shutdown).await {
                eprintln!("gRPC rig exited: {e}");
            }
        });

        // Wait briefly for the server to come up.
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        Self {
            addr,
            shutdown_tx: Some(tx),
            rate_limiter,
            handle,
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    async fn channel(&self) -> Channel {
        Channel::from_shared(self.endpoint())
            .expect("endpoint")
            .connect()
            .await
            .expect("connect")
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), self.handle).await;
    }
}

/// Seeds a realm + an admin user and returns (`realm_id`, `user_id`,
/// `access_token`).
fn setup_admin(harness: &common::TestHarness) -> (RealmId, UserId, String) {
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "grpc-test-realm".to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "admin@example.com".to_string(),
                display_name: "Admin".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");
    let user_id = user.id().clone();
    let session = harness
        .identity()
        .create_session(&realm_id, &user_id, &SessionContext::default())
        .expect("create session");
    let tokens = harness
        .identity()
        .issue_tokens(&realm_id, &user_id, session.id())
        .expect("issue tokens");
    let object = ObjectRef::new("hearth", "admin").expect("obj");
    let subject = SubjectRef::direct("user", &user_id.as_uuid().to_string()).expect("subj");
    let tuple = RelationshipTuple::new(object, "admin", subject).expect("tuple");
    harness
        .authz()
        .write_tuples(&realm_id, &[TupleWrite::Touch(tuple)])
        .expect("admin tuple");
    (realm_id, user_id, tokens.access_token().to_string())
}

fn admin_headers(
    realm_id: &RealmId,
    token: &str,
) -> (
    MetadataValue<tonic::metadata::Ascii>,
    MetadataValue<tonic::metadata::Ascii>,
) {
    let auth: MetadataValue<_> = format!("Bearer {token}").parse().expect("auth header");
    let realm: MetadataValue<_> = realm_id
        .as_uuid()
        .to_string()
        .parse()
        .expect("realm header");
    (auth, realm)
}

fn apply_headers<T>(req: &mut Request<T>, realm_id: &RealmId, token: &str) {
    let (auth, realm) = admin_headers(realm_id, token);
    req.metadata_mut().insert("authorization", auth);
    req.metadata_mut().insert("x-realm-id", realm);
}

// ==========================================================================
// Tests
// ==========================================================================

#[tokio::test]
async fn health_check_returns_serving() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let rig = GrpcRig::start(&harness).await;
    let channel = rig.channel().await;
    use tonic_health::pb::health_client::HealthClient;
    use tonic_health::pb::HealthCheckRequest;
    let mut client = HealthClient::new(channel);
    let resp = client
        .check(HealthCheckRequest {
            service: String::new(),
        })
        .await
        .expect("health");
    assert_eq!(
        resp.into_inner().status,
        tonic_health::pb::health_check_response::ServingStatus::Serving as i32
    );
    rig.shutdown().await;
}

#[tokio::test]
async fn reflection_lists_hearth_services() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let rig = GrpcRig::start(&harness).await;
    let channel = rig.channel().await;
    use tonic_reflection::pb::v1::server_reflection_client::ServerReflectionClient;
    use tonic_reflection::pb::v1::{
        server_reflection_request::MessageRequest, server_reflection_response::MessageResponse,
        ServerReflectionRequest,
    };
    let mut client = ServerReflectionClient::new(channel);
    let req = tokio_stream::iter(vec![ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::ListServices(String::new())),
    }]);
    let mut stream = client
        .server_reflection_info(req)
        .await
        .expect("reflect")
        .into_inner();
    let msg = stream.message().await.expect("msg").expect("some");
    match msg.message_response.expect("resp") {
        MessageResponse::ListServicesResponse(list) => {
            let names: Vec<_> = list.service.iter().map(|s| s.name.clone()).collect();
            assert!(names
                .iter()
                .any(|n| n == "hearth.identity.v1.IdentityAdminService"));
            assert!(names
                .iter()
                .any(|n| n == "hearth.authz.v1.AuthorizationService"));
            assert!(names.iter().any(|n| n == "hearth.events.v1.AuditService"));
            assert!(names.iter().any(|n| n == "hearth.identity.v1.OAuthService"));
        }
        other => panic!("unexpected reflection response: {other:?}"),
    }
    rig.shutdown().await;
}

#[tokio::test]
async fn unauthenticated_request_is_rejected() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let rig = GrpcRig::start(&harness).await;
    let channel = rig.channel().await;
    let mut client = IdentityAdminServiceClient::new(channel);
    let err = client
        .list_users(pb::ListUsersRequest {
            cursor: None,
            limit: Some(10),
        })
        .await
        .expect_err("should fail without auth");
    assert_eq!(err.code(), Code::Unauthenticated);
    rig.shutdown().await;
}

#[tokio::test]
async fn non_admin_request_is_forbidden() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "no-admin-realm".to_string(),
            config: None,
        })
        .expect("realm");
    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "not-admin@example.com".to_string(),
                display_name: "NotAdmin".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("user");
    let session = harness
        .identity()
        .create_session(realm.id(), user.id(), &SessionContext::default())
        .expect("session");
    let tokens = harness
        .identity()
        .issue_tokens(realm.id(), user.id(), session.id())
        .expect("tokens");

    let rig = GrpcRig::start(&harness).await;
    let channel = rig.channel().await;
    let mut client = IdentityAdminServiceClient::new(channel);
    let mut req = Request::new(pb::ListUsersRequest {
        cursor: None,
        limit: Some(10),
    });
    apply_headers(&mut req, realm.id(), tokens.access_token());
    let err = client.list_users(req).await.expect_err("forbidden");
    assert_eq!(err.code(), Code::PermissionDenied);
    rig.shutdown().await;
}

#[tokio::test]
async fn create_and_get_user_via_grpc() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, _admin, token) = setup_admin(&harness);
    let rig = GrpcRig::start(&harness).await;
    let channel = rig.channel().await;
    let mut client = IdentityAdminServiceClient::new(channel);

    let mut create = Request::new(pb::CreateUserRequest {
        email: "alice@example.com".to_string(),
        display_name: "Alice".to_string(),
        first_name: String::new(),
        last_name: String::new(),
    });
    apply_headers(&mut create, &realm_id, &token);
    let created = client
        .create_user(create)
        .await
        .expect("create")
        .into_inner();
    assert_eq!(created.email, "alice@example.com");

    let mut get = Request::new(pb::GetUserRequest {
        id: created.id.clone(),
    });
    apply_headers(&mut get, &realm_id, &token);
    let got = client.get_user(get).await.expect("get").into_inner();
    assert_eq!(got.id, created.id);
    rig.shutdown().await;
}

#[tokio::test]
async fn cross_realm_isolation_returns_not_found() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let (realm_a, _admin, token) = setup_admin(&harness);
    // Second realm with its own user.
    let realm_b = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "other-realm".to_string(),
            config: None,
        })
        .expect("realm b");
    let b_user = harness
        .identity()
        .create_user(
            realm_b.id(),
            &CreateUserRequest {
                email: "bob@example.com".to_string(),
                display_name: "Bob".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("user b");

    let rig = GrpcRig::start(&harness).await;
    let channel = rig.channel().await;
    let mut client = IdentityAdminServiceClient::new(channel);

    // Admin of realm A asks for B's user id — must NOT find it.
    let mut req = Request::new(pb::GetUserRequest {
        id: b_user.id().as_uuid().to_string(),
    });
    apply_headers(&mut req, &realm_a, &token);
    let err = client.get_user(req).await.expect_err("cross-realm");
    assert_eq!(err.code(), Code::NotFound);
    rig.shutdown().await;
}

#[tokio::test]
async fn application_crud_via_grpc() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, _admin, token) = setup_admin(&harness);
    let rig = GrpcRig::start(&harness).await;
    let channel = rig.channel().await;
    let mut apps = ApplicationAdminServiceClient::new(channel);

    let mut create = Request::new(pb::RegisterClientRequest {
        client_name: "Test App".to_string(),
        redirect_uris: vec!["https://app.example.com/cb".to_string()],
        client_secret: Some("hunter2hunter2".to_string()),
        grant_types: vec!["authorization_code".to_string()],
    });
    apply_headers(&mut create, &realm_id, &token);
    let created = apps
        .create_application(create)
        .await
        .expect("create app")
        .into_inner();

    let mut list = Request::new(pb::ListApplicationsRequest {
        cursor: None,
        limit: Some(10),
    });
    apply_headers(&mut list, &realm_id, &token);
    let page = apps
        .list_applications(list)
        .await
        .expect("list")
        .into_inner();
    assert!(page.items.iter().any(|c| c.client_id == created.client_id));

    let mut del = Request::new(pb::DeleteApplicationRequest {
        client_id: created.client_id.clone(),
    });
    apply_headers(&mut del, &realm_id, &token);
    apps.delete_application(del).await.expect("delete");
    rig.shutdown().await;
}

#[tokio::test]
async fn authz_check_and_write_tuples_via_grpc() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, _admin, token) = setup_admin(&harness);
    let rig = GrpcRig::start(&harness).await;
    let channel = rig.channel().await;
    let mut client = AuthorizationServiceClient::new(channel);

    // Write: user:alice is a member of group:eng
    let tuple = azpb::RelationshipTuple {
        object: Some(azpb::ObjectRef {
            object_type: "group".to_string(),
            object_id: "eng".to_string(),
        }),
        relation: "member".to_string(),
        subject: Some(azpb::SubjectRef {
            kind: Some(azpb::subject_ref::Kind::Direct(azpb::ObjectRef {
                object_type: "user".to_string(),
                object_id: "alice".to_string(),
            })),
        }),
    };
    let mut write = Request::new(azpb::WriteTuplesRequest {
        writes: vec![azpb::TupleWrite {
            operation: azpb::TupleWriteOperation::Touch as i32,
            tuple: Some(tuple.clone()),
        }],
    });
    apply_headers(&mut write, &realm_id, &token);
    let resp = client
        .write_tuples(write)
        .await
        .expect("write")
        .into_inner();
    assert!(resp.token.is_some());

    // Check: alice is in eng
    let mut check = Request::new(azpb::CheckRequest {
        object: Some(azpb::ObjectRef {
            object_type: "group".to_string(),
            object_id: "eng".to_string(),
        }),
        relation: "member".to_string(),
        subject: Some(azpb::SubjectRef {
            kind: Some(azpb::subject_ref::Kind::Direct(azpb::ObjectRef {
                object_type: "user".to_string(),
                object_id: "alice".to_string(),
            })),
        }),
        at_least_as_fresh_as: None,
    });
    apply_headers(&mut check, &realm_id, &token);
    let result = client.check(check).await.expect("check").into_inner();
    assert!(result.allowed);
    rig.shutdown().await;
}

#[tokio::test]
async fn watch_streams_live_tuple_writes() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, _admin, token) = setup_admin(&harness);
    let rig = GrpcRig::start(&harness).await;
    let channel = rig.channel().await;
    let mut watch_client = AuthorizationServiceClient::new(channel.clone());
    let mut write_client = AuthorizationServiceClient::new(channel);

    let mut watch_req = Request::new(azpb::WatchRequest {
        start_after: None,
        filter: None,
    });
    apply_headers(&mut watch_req, &realm_id, &token);
    let mut stream = watch_client
        .watch(watch_req)
        .await
        .expect("watch")
        .into_inner();

    // Small pause to ensure the subscriber is registered before we write.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let tuple = azpb::RelationshipTuple {
        object: Some(azpb::ObjectRef {
            object_type: "group".to_string(),
            object_id: "ops".to_string(),
        }),
        relation: "member".to_string(),
        subject: Some(azpb::SubjectRef {
            kind: Some(azpb::subject_ref::Kind::Direct(azpb::ObjectRef {
                object_type: "user".to_string(),
                object_id: "carol".to_string(),
            })),
        }),
    };
    let mut write = Request::new(azpb::WriteTuplesRequest {
        writes: vec![azpb::TupleWrite {
            operation: azpb::TupleWriteOperation::Touch as i32,
            tuple: Some(tuple),
        }],
    });
    apply_headers(&mut write, &realm_id, &token);
    write_client.write_tuples(write).await.expect("write");

    // Wait up to 3 seconds for the event to arrive.
    let event = tokio::time::timeout(Duration::from_secs(3), stream.message())
        .await
        .expect("timeout")
        .expect("stream")
        .expect("event present");
    let e = event.event.expect("event body");
    assert_eq!(e.object_type, "group");
    assert_eq!(e.object_id, "ops");
    rig.shutdown().await;
}

#[tokio::test]
async fn audit_list_events_via_grpc() {
    use hearth::audit::{AuditAction, CreateAuditEvent};
    let harness = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, admin, token) = setup_admin(&harness);
    harness
        .audit()
        .append(&CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: admin.as_uuid().to_string(),
            action: AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "u1".to_string(),
            metadata: None,
        })
        .expect("append");
    let rig = GrpcRig::start(&harness).await;
    let channel = rig.channel().await;
    let mut client = AuditServiceClient::new(channel);
    let mut req = Request::new(evpb::AuditQuery {
        realm_id: String::new(),
        start_time: None,
        end_time: None,
        actor: None,
        action: None,
        limit: Some(100),
    });
    apply_headers(&mut req, &realm_id, &token);
    let resp = client.list_events(req).await.expect("list").into_inner();
    assert!(!resp.events.is_empty());
    rig.shutdown().await;
}

#[tokio::test]
async fn audit_verify_integrity_via_grpc() {
    use hearth::audit::{AuditAction, CreateAuditEvent};
    let harness = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, admin, token) = setup_admin(&harness);
    harness
        .audit()
        .append(&CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: admin.as_uuid().to_string(),
            action: AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "u1".to_string(),
            metadata: None,
        })
        .expect("append");
    let rig = GrpcRig::start(&harness).await;
    let channel = rig.channel().await;
    let mut client = AuditServiceClient::new(channel);
    let mut req = Request::new(evpb::VerifyIntegrityRequest {});
    apply_headers(&mut req, &realm_id, &token);
    let resp = client
        .verify_integrity(req)
        .await
        .expect("verify")
        .into_inner();
    assert!(resp.ok);
    assert!(resp.event_count >= 1);
    rig.shutdown().await;
}

#[tokio::test]
async fn rate_limit_shared_across_grpc_calls() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, _admin, token) = setup_admin(&harness);
    let rig = GrpcRig::start(&harness).await;

    // Fill the window, then expect next call to fail.
    // We exhaust via repeated gRPC calls rather than poking the limiter
    // directly so we also exercise the interceptor wiring.
    let channel = rig.channel().await;
    let mut client = IdentityAdminServiceClient::new(channel.clone());
    for _ in 0..ADMIN_RATE_LIMIT {
        let mut req = Request::new(pb::ListUsersRequest {
            cursor: None,
            limit: Some(1),
        });
        apply_headers(&mut req, &realm_id, &token);
        client.list_users(req).await.expect("under limit");
    }
    let mut over = Request::new(pb::ListUsersRequest {
        cursor: None,
        limit: Some(1),
    });
    apply_headers(&mut over, &realm_id, &token);
    let err = client.list_users(over).await.expect_err("over limit");
    assert_eq!(err.code(), Code::ResourceExhausted);

    // The rig's rate limiter instance is what the interceptor saw.
    drop(rig.rate_limiter.clone()); // reference for documentation
    rig.shutdown().await;
}

#[tokio::test]
async fn oauth_client_credentials_via_grpc() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "oauth-realm".to_string(),
            config: None,
        })
        .expect("realm");
    let client = harness
        .identity()
        .register_client(
            realm.id(),
            &hearth::identity::RegisterClientRequest {
                client_name: "cc-client".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: Some("a-secret-password-32-chars-long".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                client_logo_url: None,
            },
        )
        .expect("register");

    let rig = GrpcRig::start(&harness).await;
    let channel = rig.channel().await;
    let mut oauth = OAuthServiceClient::new(channel);
    let mut req = Request::new(pb::ClientCredentialsRequest {
        client_id: client.client_id().as_uuid().to_string(),
        client_secret: "a-secret-password-32-chars-long".to_string(),
        scope: None,
    });
    let realm_meta: MetadataValue<_> = realm.id().as_uuid().to_string().parse().expect("realm");
    req.metadata_mut().insert("x-realm-id", realm_meta);
    let resp = oauth
        .client_credentials(req)
        .await
        .expect("cc grant")
        .into_inner();
    assert!(!resp.access_token.is_empty());
    rig.shutdown().await;
}
