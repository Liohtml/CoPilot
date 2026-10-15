//! Where the port stops on purpose: what Python would run without end, or
//! cannot even compile.

use copilot_jinja::{Event, render};

fn event() -> Event {
    Event {
        customer_code: Some("ACME".into()),
        trigger: "temp_password_issued".into(),
        severity: "Informational".into(),
        subject: "s".into(),
        summary: "s".into(),
        entity_type: "user".into(),
        entity_id: 1,
        dedupe_key: "k".into(),
        link_url: None,
        assignee_username: None,
        actor_username: None,
        context: Vec::new(),
    }
}

fn kind(source: &str) -> &'static str {
    match render(source, &event(), false, &[]) {
        Ok(_) => "ok",
        Err(e) => e.kind,
    }
}

#[test]
fn an_unbounded_loop_is_stopped() {
    let src = "{% for i in range(100000) %}{% for j in range(100) %}{% endfor %}{% endfor %}";
    assert_eq!(kind(src), "RuntimeError");
}

#[test]
fn a_slice_outside_a_subscript_does_not_compile() {
    assert_eq!(kind("{{ x[1:2, 3] }}"), "SyntaxError");
}

#[test]
fn deep_recursion_is_a_recursion_error() {
    assert_eq!(
        kind("{% macro r(n) %}{{ r(n + 1) }}{% endmacro %}{{ r(0) }}"),
        "RecursionError"
    );
    let nested = format!("{}1{}", "[".repeat(300), "]".repeat(300));
    assert_eq!(kind(&format!("{{{{ {nested} }}}}")), "RecursionError");
}

#[test]
fn output_past_the_limit_is_counted_not_kept() {
    let err = render(
        "{% for i in range(100) %}{{ 'x' * 100000 }}{% endfor %}",
        &event(),
        false,
        &[],
    )
    .unwrap_err();
    assert_eq!(err.kind, "TemplateTooLargeError");
    assert!(
        err.message.starts_with("Rendered body is 10000000 bytes"),
        "{}",
        err.message
    );
}
