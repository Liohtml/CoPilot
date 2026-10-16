//! `/api/portainer/*` — port of `app/connectors/portainer/routes/portainer.py`
//! but `POST /create-wazuh-customer-stack` (it reads the Wazuh manager's
//! version and the customer provisioning schema, both still Python): eight
//! routes, `require_any_scope("admin", "analyst")` for `/node-details`,
//! `require_any_scope("admin")` for the rest, as in Python. Admins are
//! deployment-wide, so no route is tenant-scoped.

use axum::Router;
use axum::extract::State;
use axum::routing::{delete, get, post};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{self, Loc, PyError, Ty};
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::{model_response, validation_error};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, QueryPairs,
};

use crate::client::PortainerClient;
use crate::services;

/// Route state.
#[derive(Debug, Clone)]
pub struct PortainerState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The Portainer client.
    pub client: PortainerClient,
}

impl axum::extract::FromRef<PortainerState> for AppContext {
    fn from_ref(s: &PortainerState) -> AppContext {
        s.ctx.clone()
    }
}

type Reader = Authorized<AdminOrAnalyst>;
type Admin = Authorized<AdminOnly>;

/// The router, to be nested at `/api/portainer`.
pub fn router(state: PortainerState) -> Router {
    Router::new()
        .route("/node-details", get(node_details))
        .route("/stacks", get(stacks))
        .route("/stack-details", get(stack_details))
        .route("/get-customer-stack-id", get(get_customer_stack_id))
        .route("/start-wazuh-customer-stack", post(start_stack))
        .route("/stop-wazuh-customer-stack", post(stop_stack))
        .route("/update-customer-stack-id", post(update_customer_stack_id))
        .route("/delete-wazuh-customer-stack", delete(delete_stack))
        .with_state(state)
}

fn answer(result: Result<PyValue, PyExc>) -> ApiResult {
    result
        .map(|dump| model_response(&dump))
        .map_err(PyExc::unhandled)
}

/// Required query parameters, read in declaration order with every error
/// collected (FastAPI's 422).
#[derive(Default)]
struct Query {
    errors: Vec<PyError>,
}

impl Query {
    fn missing(&mut self, name: &str) {
        self.errors.push(PyError {
            loc: vec![Loc::Key(name.into())],
            kind: "missing",
            msg: "Field required".into(),
            input: PyValue::None,
        });
    }

    fn str(&mut self, q: &QueryPairs, name: &str) -> String {
        match q.get(name) {
            Some(v) => v.to_string(),
            None => {
                self.missing(name);
                String::new()
            }
        }
    }

    /// `name: int`: Python's `int` text.
    fn int(&mut self, q: &QueryPairs, name: &str) -> String {
        let Some(raw) = q.get(name) else {
            self.missing(name);
            return String::new();
        };
        match model::validate_ty(&Ty::Int, &PyValue::Str(raw.to_string())) {
            Ok(v) => v.py_str(),
            Err(model::Invalid::Errors(errors)) => {
                self.errors.extend(errors.into_iter().map(|mut e| {
                    e.loc.insert(0, Loc::Key(name.into()));
                    e
                }));
                String::new()
            }
            Err(model::Invalid::Abort(..)) => String::new(),
        }
    }

    fn finish(self) -> Result<(), ApiError> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(validation_error(self.errors, "query"))
        }
    }
}

fn stack_id(q: &QueryPairs) -> Result<String, ApiError> {
    let mut check = Query::default();
    let id = check.int(q, "stack_id");
    check.finish()?;
    Ok(id)
}

async fn node_details(_: Reader, State(st): State<PortainerState>) -> ApiResult {
    answer(services::node_details(&st.client).await)
}

async fn stacks(_: Admin, State(st): State<PortainerState>) -> ApiResult {
    answer(services::stacks(&st.client).await)
}

async fn stack_details(_: Admin, State(st): State<PortainerState>, q: QueryPairs) -> ApiResult {
    let id = stack_id(&q)?;
    answer(services::stack_details(&st.client, &id).await)
}

async fn get_customer_stack_id(
    _: Admin,
    State(st): State<PortainerState>,
    q: QueryPairs,
) -> ApiResult {
    let mut check = Query::default();
    let name = check.str(&q, "customer_name");
    check.finish()?;
    answer(services::customer_stack_id(&st.ctx.db, &name).await)
}

async fn start_stack(_: Admin, State(st): State<PortainerState>, q: QueryPairs) -> ApiResult {
    let id = stack_id(&q)?;
    answer(services::start_stack(&st.client, &id).await)
}

async fn stop_stack(_: Admin, State(st): State<PortainerState>, q: QueryPairs) -> ApiResult {
    let id = stack_id(&q)?;
    answer(services::stop_stack(&st.client, &id).await)
}

async fn update_customer_stack_id(
    _: Admin,
    State(st): State<PortainerState>,
    q: QueryPairs,
) -> ApiResult {
    let mut check = Query::default();
    let name = check.str(&q, "customer_name");
    let id = check.int(&q, "stack_id");
    check.finish()?;
    answer(services::update_customer_stack_id(&st.ctx.db, &name, &id).await)
}

async fn delete_stack(_: Admin, State(st): State<PortainerState>, q: QueryPairs) -> ApiResult {
    let id = stack_id(&q)?;
    answer(services::delete_stack(&st.client, &id).await)
}
