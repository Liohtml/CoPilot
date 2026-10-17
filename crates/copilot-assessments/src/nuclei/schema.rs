//! `app/integrations/nuclei/schema/nuclei.py`.

use copilot_upstream::model::{Field, Model, Ty};

/// The module path Python names in a `Model(**answer)` `TypeError`.
pub const MODULE: &str = "app.integrations.nuclei.schema.nuclei";

/// `NucleiScanResponse`.
pub static SCAN_RESPONSE: Model = Model::new(
    "NucleiScanResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);

/// `NucleiReportsAvailableResponse`.
pub static REPORTS_RESPONSE: Model = Model::new(
    "NucleiReportsAvailableResponse",
    &[
        Field::req("reports", Ty::List(&Ty::Str)),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `NucleiReportCollectionResponse`.
pub static REPORT_RESPONSE: Model = Model::new(
    "NucleiReportCollectionResponse",
    &[
        Field::req("markdown", Ty::Str),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `DeleteNucleiReportResponse`.
pub static DELETE_RESPONSE: Model = Model::new(
    "DeleteNucleiReportResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);
