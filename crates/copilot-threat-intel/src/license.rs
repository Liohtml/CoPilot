//! The licence check the threat-intel routes need — `get_license` and
//! `is_feature_enabled` of `app/middleware/license.py` — which is
//! `copilot-license`'s, called with this module's licence server URL
//! ([`crate::urls::Urls::license`]) so the parity harness can point it at a
//! stand-in.

use copilot_license::LicenseClient;
use copilot_upstream::py::PyResult;

use crate::ThreatIntelState;

fn client(st: &ThreatIntelState) -> LicenseClient {
    LicenseClient {
        http: st.license_http.clone(),
        base: st.urls.license.clone(),
        api_key: st.api_key.clone(),
    }
}

/// `get_license(session)`: the first row's key, or the 404.
pub async fn license_key(st: &ThreatIntelState) -> PyResult<String> {
    copilot_license::license_key(&st.ctx.db).await
}

/// `is_feature_enabled(feature_name, session)`.
pub async fn is_feature_enabled(st: &ThreatIntelState, feature: &str) -> PyResult<()> {
    copilot_license::is_feature_enabled(&st.ctx.db, &client(st), feature).await
}
