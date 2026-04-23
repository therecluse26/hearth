//! `AuthorizationService` gRPC implementation, including `Watch` streaming.

use std::pin::Pin;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::authz::{ConsistencyToken, WatchFilter};
use crate::protocol::convert::authz::{
    proto_object_ref_to_domain, proto_subject_ref_to_domain, proto_tuple_write_to_domain,
};
use crate::protocol::proto::authz::v1 as pb;
use crate::protocol::proto::authz::v1::authorization_service_server::AuthorizationService;

use super::auth::authenticate_admin;
use super::convert::authz_to_status;
use super::server::GrpcState;

pub struct AuthzSvc {
    state: GrpcState,
}

impl AuthzSvc {
    pub fn new(state: GrpcState) -> Self {
        Self { state }
    }
}

/// Server-streaming channel buffer — keeps memory bounded if a client stops
/// reading. Events are dropped and the watch is closed on overflow rather
/// than blocking the engine's broadcast publisher.
const WATCH_CHANNEL_BUFFER: usize = 256;

pub type WatchStream = Pin<Box<dyn Stream<Item = Result<pb::WatchEvent, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl AuthorizationService for AuthzSvc {
    async fn check(
        &self,
        req: Request<pb::CheckRequest>,
    ) -> Result<Response<pb::CheckResponse>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let object = body
            .object
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("object required"))
            .and_then(|o| proto_object_ref_to_domain(o).map_err(Status::invalid_argument))?;
        let subject = body
            .subject
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("subject required"))
            .and_then(|s| proto_subject_ref_to_domain(s).map_err(Status::invalid_argument))?;
        let at_least = body
            .at_least_as_fresh_as
            .as_ref()
            .map(|t| ConsistencyToken::new(t.version));
        let allowed = self
            .state
            .authz
            .check(
                &auth.realm_id,
                &object,
                &body.relation,
                &subject,
                at_least.as_ref(),
            )
            .map_err(authz_to_status)?;
        Ok(Response::new(pb::CheckResponse {
            allowed,
            token: Some(pb::ConsistencyToken {
                version: at_least.map_or(0, |t| t.version()),
            }),
        }))
    }

    async fn expand(
        &self,
        req: Request<pb::ExpandRequest>,
    ) -> Result<Response<pb::ExpandResponse>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let object = body
            .object
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("object required"))
            .and_then(|o| proto_object_ref_to_domain(o).map_err(Status::invalid_argument))?;
        let at_least = body
            .at_least_as_fresh_as
            .as_ref()
            .map(|t| ConsistencyToken::new(t.version));
        let subjects = self
            .state
            .authz
            .expand(&auth.realm_id, &object, &body.relation, at_least.as_ref())
            .map_err(authz_to_status)?;
        Ok(Response::new(pb::ExpandResponse {
            token: Some(pb::ConsistencyToken {
                version: at_least.map_or(0, |t| t.version()),
            }),
            subjects: subjects.iter().map(pb::SubjectRef::from).collect(),
        }))
    }

    async fn write_tuples(
        &self,
        req: Request<pb::WriteTuplesRequest>,
    ) -> Result<Response<pb::WriteTuplesResponse>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let writes: Vec<_> = body
            .writes
            .iter()
            .map(proto_tuple_write_to_domain)
            .collect::<Result<_, _>>()
            .map_err(Status::invalid_argument)?;
        let token = self
            .state
            .authz
            .write_tuples(&auth.realm_id, &writes)
            .map_err(authz_to_status)?;
        Ok(Response::new(pb::WriteTuplesResponse {
            token: Some(pb::ConsistencyToken::from(token)),
        }))
    }

    type WatchStream = WatchStream;

    async fn watch(
        &self,
        req: Request<pb::WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let filter = WatchFilter {
            object_type: body.filter.as_ref().and_then(|f| f.object_type.clone()),
        };
        let resume_from = body
            .start_after
            .as_ref()
            .map(|t| ConsistencyToken::new(t.version));
        let mut receiver = self
            .state
            .authz
            .watch(&auth.realm_id, &filter, resume_from.as_ref())
            .map_err(authz_to_status)?;

        let (tx, rx) = mpsc::channel(WATCH_CHANNEL_BUFFER);

        tokio::spawn(async move {
            // Replay prefix first (events persisted since `start_after`).
            while let Some(event) = receiver.drain_replay() {
                let msg = pb::WatchEvent {
                    token: Some(pb::ConsistencyToken {
                        version: event.sequence,
                    }),
                    event: Some(pb::TupleChangeEvent::from(&event)),
                };
                if tx.send(Ok(msg)).await.is_err() {
                    return;
                }
            }
            // Then live events from the broadcast channel.
            while let Some(event) = receiver.recv().await {
                let msg = pb::WatchEvent {
                    token: Some(pb::ConsistencyToken {
                        version: event.sequence,
                    }),
                    event: Some(pb::TupleChangeEvent::from(&event)),
                };
                if tx.send(Ok(msg)).await.is_err() {
                    return;
                }
            }
        });

        let stream: WatchStream = Box::pin(ReceiverStream::new(rx));
        Ok(Response::new(stream))
    }
}
