//! `app/connectors/shuffle/schema/singul.py`.

use copilot_upstream::model::{Field, Model, Ty};

/// `SingulRequest`.
pub static SINGUL_REQUEST: Model = Model::new("SingulRequest", &[Field::req("app", Ty::Str)]);
