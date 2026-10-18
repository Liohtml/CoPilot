//! The Pydantic models of `app/middleware/license.py`, as
//! [`copilot_upstream::model`] statics: the request bodies the routes
//! validate and the models they build from the licence server's answers
//! (whose `ValidationError` is the `ValueError` handler's 400).

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

fn seven() -> PyValue {
    PyValue::Int("7".into())
}

fn empty_dict() -> PyValue {
    PyValue::Dict(Vec::new())
}

fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

fn yes() -> PyValue {
    PyValue::Bool(true)
}

fn checkout_message() -> PyValue {
    PyValue::Str("Checkout session created successfully".into())
}

/// `ReplaceLicenseRequest`.
pub static REPLACE_LICENSE_REQUEST: Model = Model::new(
    "ReplaceLicenseRequest",
    &[Field::req("license_key", Ty::Str)],
);

/// `TrialLicenseRequest`.
pub static TRIAL_LICENSE_REQUEST: Model = Model::new(
    "TrialLicenseRequest",
    &[
        Field::def("period", Ty::Nullable(&Ty::Int), seven),
        Field::req("email", Ty::Str),
        Field::req("feature_name", Ty::Str),
        Field::req("customer_name", Ty::Str),
        Field::req("company_name", Ty::Str),
    ],
);

/// `TrialLicenseResponse`.
pub static TRIAL_LICENSE_RESPONSE: Model = Model::new(
    "TrialLicenseResponse",
    &[
        Field::req("license_key", Ty::Str),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `Customer`.
pub static CUSTOMER: Model = Model::new(
    "Customer",
    &[
        Field::req("id", Ty::Int),
        Field::req("name", Ty::Str),
        Field::req("email", Ty::Str),
        Field::req("companyName", Ty::Str),
        Field::req("created", Ty::DateTime),
    ],
);

/// `LicenseResponse`.
pub static LICENSE_RESPONSE: Model = Model::new(
    "LicenseResponse",
    &[
        Field::req("productId", Ty::Int),
        Field::req("id", Ty::Int),
        Field::req("key", Ty::Str),
        Field::req("created", Ty::DateTime),
        Field::req("expires", Ty::DateTime),
        Field::req("period", Ty::Int),
        Field::req("f1", Ty::Bool),
        Field::req("f2", Ty::Bool),
        Field::req("f3", Ty::Bool),
        Field::req("f4", Ty::Bool),
        Field::req("f5", Ty::Bool),
        Field::req("f6", Ty::Bool),
        Field::req("f7", Ty::Bool),
        Field::req("f8", Ty::Bool),
        Field::req("notes", Ty::Str),
        Field::req("block", Ty::Bool),
        Field::req("globalId", Ty::Int),
        Field::req("customer", Ty::Model(&CUSTOMER)),
        Field::req("activatedMachines", Ty::List(&Ty::Any)),
        Field::req("trialActivation", Ty::Bool),
        Field::req("maxNoOfMachines", Ty::Int),
        Field::opt("allowedMachines", Ty::Nullable(&Ty::Any)),
        Field::req("dataObjects", Ty::List(&Ty::Any)),
        Field::req("signDate", Ty::DateTime),
        Field::opt("reseller", Ty::Nullable(&Ty::Any)),
    ],
);

/// `VerifyLicenseResponse`.
pub static VERIFY_LICENSE_RESPONSE: Model = Model::new(
    "VerifyLicenseResponse",
    &[
        Field::req("license", Ty::Model(&LICENSE_RESPONSE)),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `GetLicenseResponse`.
pub static GET_LICENSE_RESPONSE: Model = Model::new(
    "GetLicenseResponse",
    &[
        Field::req("license_key", Ty::Str),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `GetLicenseFeaturesResponse`.
pub static GET_LICENSE_FEATURES_RESPONSE: Model = Model::new(
    "GetLicenseFeaturesResponse",
    &[
        Field::req("features", Ty::List(&Ty::Str)),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `IsFeatureEnabledResponse`.
pub static IS_FEATURE_ENABLED_RESPONSE: Model = Model::new(
    "IsFeatureEnabledResponse",
    &[
        Field::req("enabled", Ty::Bool),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `Feature`.
pub static FEATURE: Model = Model::new(
    "Feature",
    &[
        Field::req("id", Ty::Int),
        Field::req("subscription_price_id", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("price", Ty::Int),
        Field::req("currency", Ty::Str),
        Field::req("info", Ty::Str),
        Field::req("short_description", Ty::Str),
        Field::req("full_description", Ty::Str),
        Field::opt("mssp_seats", Ty::Nullable(&Ty::Int)),
    ],
);

/// `GetSubscriptionCatalogFeaturesResponse`.
pub static SUBSCRIPTION_FEATURES_RESPONSE: Model = Model::new(
    "GetSubscriptionCatalogFeaturesResponse",
    &[
        Field::req("features", Ty::List(&Ty::Model(&FEATURE))),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `FeatureSubscriptionRequest`.
pub static FEATURE_SUBSCRIPTION_REQUEST: Model = Model::new(
    "FeatureSubscriptionRequest",
    &[
        Field::req("feature_id", Ty::Int),
        Field::req("cancel_url", Ty::Str),
        Field::req("success_url", Ty::Str),
        Field::req("customer_email", Ty::Str),
        Field::req("company_name", Ty::Str),
    ],
);

/// `GetLicenseByEmailRequest`.
pub static GET_LICENSE_BY_EMAIL_REQUEST: Model =
    Model::new("GetLicenseByEmailRequest", &[Field::req("email", Ty::Str)]);

/// `AddLicenseToDB`.
pub static ADD_LICENSE_TO_DB: Model = Model::new(
    "AddLicenseToDB",
    &[
        Field::req("customer_name", Ty::Str),
        Field::req("customer_email", Ty::Str),
        Field::req("company_name", Ty::Str),
    ],
);

/// `AutomaticTax`.
pub static AUTOMATIC_TAX: Model = Model::new(
    "AutomaticTax",
    &[
        Field::req("enabled", Ty::Bool),
        Field::opt("liability", Ty::Nullable(&Ty::Str)),
        Field::opt("status", Ty::Nullable(&Ty::Str)),
    ],
);

/// `CustomText`.
pub static CUSTOM_TEXT: Model = Model::new(
    "CustomText",
    &[
        Field::opt("after_submit", Ty::Nullable(&Ty::Str)),
        Field::opt("shipping_address", Ty::Nullable(&Ty::Str)),
        Field::opt("submit", Ty::Nullable(&Ty::Str)),
        Field::opt("terms_of_service_acceptance", Ty::Nullable(&Ty::Str)),
    ],
);

/// `InvoiceData`.
pub static INVOICE_DATA: Model = Model::new(
    "InvoiceData",
    &[
        Field::opt("account_tax_ids", Ty::Nullable(&Ty::Str)),
        Field::opt("custom_fields", Ty::Nullable(&Ty::Str)),
        Field::opt("description", Ty::Nullable(&Ty::Str)),
        Field::opt("footer", Ty::Nullable(&Ty::Str)),
        Field::opt("issuer", Ty::Nullable(&Ty::Str)),
        Field::def("metadata", Ty::Dict(&Ty::Any), empty_dict),
        Field::opt("rendering_options", Ty::Nullable(&Ty::Str)),
    ],
);

/// `InvoiceCreation`.
pub static INVOICE_CREATION: Model = Model::new(
    "InvoiceCreation",
    &[
        Field::req("enabled", Ty::Bool),
        Field::req("invoice_data", Ty::Model(&INVOICE_DATA)),
    ],
);

/// `PaymentMethodOptionsCard`.
pub static PAYMENT_METHOD_OPTIONS_CARD: Model = Model::new(
    "PaymentMethodOptionsCard",
    &[Field::req("request_three_d_secure", Ty::Str)],
);

/// `PaymentMethodOptions`.
pub static PAYMENT_METHOD_OPTIONS: Model = Model::new(
    "PaymentMethodOptions",
    &[Field::req("card", Ty::Model(&PAYMENT_METHOD_OPTIONS_CARD))],
);

/// `PhoneNumberCollection`.
pub static PHONE_NUMBER_COLLECTION: Model =
    Model::new("PhoneNumberCollection", &[Field::req("enabled", Ty::Bool)]);

/// `TotalDetails`.
pub static TOTAL_DETAILS: Model = Model::new(
    "TotalDetails",
    &[
        Field::req("amount_discount", Ty::Int),
        Field::req("amount_shipping", Ty::Int),
        Field::req("amount_tax", Ty::Int),
    ],
);

/// `CustomerDetails`.
pub static CUSTOMER_DETAILS: Model = Model::new(
    "CustomerDetails",
    &[
        Field::opt("address", Ty::Nullable(&Ty::Str)),
        Field::opt("email", Ty::Nullable(&Ty::Str)),
        Field::opt("name", Ty::Nullable(&Ty::Str)),
        Field::opt("phone", Ty::Nullable(&Ty::Str)),
        Field::opt("tax_exempt", Ty::Nullable(&Ty::Str)),
        Field::opt("tax_ids", Ty::Nullable(&Ty::Str)),
    ],
);

/// `CheckoutSession`.
pub static CHECKOUT_SESSION: Model = Model::new(
    "CheckoutSession",
    &[
        Field::opt("after_expiration", Ty::Nullable(&Ty::Str)),
        Field::opt("allow_promotion_codes", Ty::Nullable(&Ty::Str)),
        Field::req("amount_subtotal", Ty::Int),
        Field::req("amount_total", Ty::Int),
        Field::req("automatic_tax", Ty::Model(&AUTOMATIC_TAX)),
        Field::opt("billing_address_collection", Ty::Nullable(&Ty::Str)),
        Field::req("cancel_url", Ty::Str),
        Field::opt("client_reference_id", Ty::Nullable(&Ty::Str)),
        Field::opt("client_secret", Ty::Nullable(&Ty::Str)),
        Field::opt("consent", Ty::Nullable(&Ty::Str)),
        Field::opt("consent_collection", Ty::Nullable(&Ty::Str)),
        Field::req("created", Ty::Int),
        Field::req("currency", Ty::Str),
        Field::opt("currency_conversion", Ty::Nullable(&Ty::Str)),
        Field::def("custom_fields", Ty::List(&Ty::Any), empty_list),
        Field::req("custom_text", Ty::Model(&CUSTOM_TEXT)),
        Field::opt("customer", Ty::Nullable(&Ty::Str)),
        Field::opt("customer_creation", Ty::Nullable(&Ty::Str)),
        Field::opt(
            "customer_details",
            Ty::Nullable(&Ty::Model(&CUSTOMER_DETAILS)),
        ),
        Field::opt("customer_email", Ty::Nullable(&Ty::Str)),
        Field::req("expires_at", Ty::Int),
        Field::req("id", Ty::Str),
        Field::opt("invoice", Ty::Nullable(&Ty::Str)),
        Field::opt(
            "invoice_creation",
            Ty::Nullable(&Ty::Model(&INVOICE_CREATION)),
        ),
        Field::req("livemode", Ty::Bool),
        Field::opt("locale", Ty::Nullable(&Ty::Str)),
        Field::req("metadata", Ty::Dict(&Ty::Any)),
        Field::req("mode", Ty::Str),
        Field::req("object", Ty::Str),
        Field::opt("payment_intent", Ty::Nullable(&Ty::Str)),
        Field::opt("payment_link", Ty::Nullable(&Ty::Str)),
        Field::req("payment_method_collection", Ty::Str),
        Field::opt(
            "payment_method_configuration_details",
            Ty::Nullable(&Ty::Str),
        ),
        Field::req("payment_method_options", Ty::Model(&PAYMENT_METHOD_OPTIONS)),
        Field::req("payment_method_types", Ty::List(&Ty::Str)),
        Field::req("payment_status", Ty::Str),
        Field::req(
            "phone_number_collection",
            Ty::Model(&PHONE_NUMBER_COLLECTION),
        ),
        Field::opt("recovered_from", Ty::Nullable(&Ty::Str)),
        Field::opt("setup_intent", Ty::Nullable(&Ty::Str)),
        Field::opt("shipping_address_collection", Ty::Nullable(&Ty::Str)),
        Field::opt("shipping_cost", Ty::Nullable(&Ty::Str)),
        Field::opt("shipping_details", Ty::Nullable(&Ty::Str)),
        Field::def("shipping_options", Ty::List(&Ty::Any), empty_list),
        Field::req("status", Ty::Str),
        Field::opt("submit_type", Ty::Nullable(&Ty::Str)),
        Field::opt("subscription", Ty::Nullable(&Ty::Str)),
        Field::req("success_url", Ty::Str),
        Field::req("total_details", Ty::Model(&TOTAL_DETAILS)),
        Field::req("ui_mode", Ty::Str),
        Field::req("url", Ty::Str),
    ],
);

/// `CheckoutSessionResponse`.
pub static CHECKOUT_SESSION_RESPONSE: Model = Model::new(
    "CheckoutSessionResponse",
    &[
        Field::def("success", Ty::Bool, yes),
        Field::def("message", Ty::Str, checkout_message),
        Field::req("session", Ty::Model(&CHECKOUT_SESSION)),
    ],
);

/// `CancelSubscriptionRequest`.
pub static CANCEL_SUBSCRIPTION_REQUEST: Model = Model::new(
    "CancelSubscriptionRequest",
    &[
        Field::req("customer_email", Ty::Str),
        Field::req("subscription_price_id", Ty::Str),
        Field::req("feature_name", Ty::Str),
    ],
);

/// `CancelSubscriptionResponse`.
pub static CANCEL_SUBSCRIPTION_RESPONSE: Model = Model::new(
    "CancelSubscriptionResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `RetrieveDockerCompose`.
pub static RETRIEVE_DOCKER_COMPOSE: Model = Model::new(
    "RetrieveDockerCompose",
    &[
        Field::req("docker_compose", Ty::Str),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// Every model of the module, for the vectors.
pub static ALL: &[&Model] = &[
    &REPLACE_LICENSE_REQUEST,
    &TRIAL_LICENSE_REQUEST,
    &TRIAL_LICENSE_RESPONSE,
    &CUSTOMER,
    &LICENSE_RESPONSE,
    &VERIFY_LICENSE_RESPONSE,
    &GET_LICENSE_RESPONSE,
    &GET_LICENSE_FEATURES_RESPONSE,
    &IS_FEATURE_ENABLED_RESPONSE,
    &FEATURE,
    &SUBSCRIPTION_FEATURES_RESPONSE,
    &FEATURE_SUBSCRIPTION_REQUEST,
    &GET_LICENSE_BY_EMAIL_REQUEST,
    &ADD_LICENSE_TO_DB,
    &CHECKOUT_SESSION,
    &CHECKOUT_SESSION_RESPONSE,
    &CANCEL_SUBSCRIPTION_REQUEST,
    &CANCEL_SUBSCRIPTION_RESPONSE,
    &RETRIEVE_DOCKER_COMPOSE,
];

#[cfg(test)]
mod vectors {
    //! `license_vectors.json` (`scripts/gen-platform-vectors.py`): every
    //! licence model built from keyword arguments, against pydantic.

    use super::*;
    use copilot_auth::pyvalue::loads;
    use copilot_upstream::json::pydantic_json;
    use copilot_upstream::model::construct;

    fn by_name(name: &str) -> &'static Model {
        ALL.iter()
            .copied()
            .find(|m| m.name == name)
            .unwrap_or_else(|| panic!("no model {name}"))
    }

    #[test]
    fn models_validate_and_dump_like_pydantic() {
        let doc = loads(include_str!("license_vectors.json")).unwrap();
        let PyValue::List(cases) = doc.get("models").unwrap().clone() else {
            panic!("models")
        };
        assert!(!cases.is_empty());
        for case in cases {
            let name = case.get("model").and_then(PyValue::as_str).unwrap();
            let kwargs = case.get("kwargs").unwrap();
            let got = construct(by_name(name), kwargs);
            match (case.get("json"), case.get("error")) {
                (Some(want), None) => {
                    let dump = got.unwrap_or_else(|e| panic!("{name}: {}", e.text()));
                    let ours: serde_json::Value =
                        serde_json::from_str(&pydantic_json(&dump)).unwrap();
                    let theirs: serde_json::Value = serde_json::from_str(
                        &copilot_upstream::json::py_dumps(
                            want,
                            copilot_upstream::json::Dumps::DEFAULT,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                    assert_eq!(ours, theirs, "{name}");
                }
                (None, Some(PyValue::Str(want))) => {
                    assert_eq!(got.unwrap_err().text(), *want, "{name}");
                }
                other => panic!("bad vector {other:?}"),
            }
        }
    }
}
