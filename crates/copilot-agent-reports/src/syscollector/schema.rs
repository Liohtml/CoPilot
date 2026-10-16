//! `app/agents/wazuh/syscollector/schema/packages.py`.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

fn zero() -> PyValue {
    PyValue::Int("0".into())
}

const OPT_STR: Ty = Ty::Nullable(&Ty::Str);

/// `PackageItem` (`extra="allow"`).
pub static PACKAGE_ITEM: Model = Model::allowing_extra(
    "PackageItem",
    &[
        Field::opt("architecture", OPT_STR),
        Field::opt("description", OPT_STR),
        Field::opt("format", OPT_STR),
        Field::opt("name", OPT_STR),
        Field::opt("priority", OPT_STR),
        Field::opt("scan", Ty::Nullable(&Ty::Dict(&Ty::Any))),
        Field::opt("section", OPT_STR),
        Field::opt("size", Ty::Nullable(&Ty::Int)),
        Field::opt("vendor", OPT_STR),
        Field::opt("version", OPT_STR),
        Field::opt("agent_id", OPT_STR),
    ],
);

/// `AgentPackagesResponse`.
pub static AGENT_PACKAGES_RESPONSE: Model = Model::new(
    "AgentPackagesResponse",
    &[
        Field::def("packages", Ty::List(&Ty::Model(&PACKAGE_ITEM)), empty_list),
        Field::def("total_affected_items", Ty::Int, zero),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `IndexerPackageAgent`.
pub static INDEXER_PACKAGE_AGENT: Model = Model::new(
    "IndexerPackageAgent",
    &[
        Field::opt("id", OPT_STR),
        Field::opt("name", OPT_STR),
        Field::opt("version", OPT_STR),
    ],
);

/// `IndexerPackageDetail`.
pub static INDEXER_PACKAGE_DETAIL: Model = Model::new(
    "IndexerPackageDetail",
    &[
        Field::opt("architecture", OPT_STR),
        Field::opt("description", OPT_STR),
        Field::opt("name", OPT_STR),
        Field::opt("size", Ty::Nullable(&Ty::Int)),
        Field::opt("type", OPT_STR),
        Field::opt("vendor", OPT_STR),
        Field::opt("version", OPT_STR),
    ],
);

/// `IndexerPackageItem` (`populate_by_name=True, extra="allow"`; built from
/// its aliases).
pub static INDEXER_PACKAGE_ITEM: Model = Model::allowing_extra(
    "IndexerPackageItem",
    &[
        Field::opt("index", OPT_STR).alias("_index"),
        Field::opt("id", OPT_STR).alias("_id"),
        Field::opt("agent", Ty::Nullable(&Ty::Model(&INDEXER_PACKAGE_AGENT))),
        Field::opt("package", Ty::Nullable(&Ty::Model(&INDEXER_PACKAGE_DETAIL))),
    ],
);

/// `IndexerPackagesResponse`.
pub static INDEXER_PACKAGES_RESPONSE: Model = Model::new(
    "IndexerPackagesResponse",
    &[
        Field::def(
            "packages",
            Ty::List(&Ty::Model(&INDEXER_PACKAGE_ITEM)),
            empty_list,
        ),
        Field::def("total", Ty::Int, zero),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);
