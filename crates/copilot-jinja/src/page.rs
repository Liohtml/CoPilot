//! `render_html_template(template_path, context)` of
//! `app/incidents/services/reports_pdf.py`: a `SandboxedEnvironment` with
//! autoescaping and Jinja2's default `Undefined` (a missing attribute prints
//! as nothing; using it further fails), the report pages CoPilot renders to
//! PDF. The templates are the backend's files, compiled in by the crate that
//! renders them; there is no loader, so `extends`/`include` fail as they do
//! without one.

use std::rc::Rc;

use crate::arena;
use crate::compiler;
use crate::error::{Error, Result};
use crate::notify::{Input, input_value};
use crate::value::{UndefinedMode, Value};
use crate::vm;

/// The stack a page renders on.
const STACK_SIZE: usize = 256 << 20;

fn render_here(source: &str, context: &[(String, Input)], autoescape: bool) -> Result<String> {
    // Jinja2's default `Undefined`, not the notification renderer's strict one.
    let _mode = UndefinedMode::set(false);
    let _guard = arena::RenderGuard::new();
    let template = compiler::compile(source, autoescape)?;
    let vars: Vec<(Rc<str>, Value)> = context
        .iter()
        .map(|(k, v)| (Rc::from(k.as_str()), input_value(v)))
        .collect();
    Ok(vm::render(&template, vars, usize::MAX)?.text)
}

/// `template.render(context)` of a page template.
pub fn render_page(source: &str, context: &[(String, Input)], autoescape: bool) -> Result<String> {
    let source = source.to_string();
    let context = context.to_vec();
    let handle = std::thread::Builder::new()
        .name("copilot-jinja-page".into())
        .stack_size(STACK_SIZE)
        .spawn(move || render_here(&source, &context, autoescape))
        .map_err(|e| {
            Error::new(
                "RuntimeError",
                format!("could not start the template engine: {e}"),
            )
        })?;
    handle
        .join()
        .unwrap_or_else(|_| Err(Error::new("RuntimeError", "the template engine failed")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn undefined_is_jinjas_default() {
        let ctx = vec![(
            "a".to_string(),
            Input::Dict(vec![("b".into(), Input::Str("<x>".into()))]),
        )];
        assert_eq!(
            render_page(
                "{{ a.b }}|{{ a.c }}|{% if a.c %}y{% endif %}|{{ a.c|length }}",
                &ctx,
                true
            )
            .unwrap(),
            "&lt;x&gt;|||0"
        );
        assert!(render_page("{{ a.c.d }}", &ctx, true).is_err());
        assert!(render_page("{{ nope }}", &[], false).unwrap().is_empty());
    }
}
