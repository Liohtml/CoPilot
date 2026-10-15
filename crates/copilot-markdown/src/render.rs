//! `RendererHTML` with the render rules `markdown_html.py` installs
//! (inline styles on tables, cells, blockquotes and code). Options are the
//! `gfm-like` preset's: `xhtmlOut` on, `breaks` off.

use crate::pystr::escape_html;
use crate::token::Token;
use crate::{BLOCKQUOTE_STYLE, CODE_STYLE, PRE_STYLE, TABLE_STYLE, TD_STYLE, TH_STYLE};

/// `render(tokens)`.
pub(crate) fn render(tokens: &[Token]) -> String {
    let mut out = String::new();
    for i in 0..tokens.len() {
        let t = &tokens[i];
        if t.ty == "inline" {
            if let Some(children) = t.children.as_deref().filter(|c| !c.is_empty()) {
                out.push_str(&render_inline(children));
            }
        } else {
            out.push_str(&rule(tokens, i));
        }
    }
    out
}

fn render_inline(tokens: &[Token]) -> String {
    (0..tokens.len()).map(|i| rule(tokens, i)).collect()
}

fn rule(tokens: &[Token], idx: usize) -> String {
    let t = &tokens[idx];
    match t.ty {
        "table_open" => format!("<table style=\"{TABLE_STYLE}\">"),
        "th_open" => cell("th", TH_STYLE, t),
        "td_open" => cell("td", TD_STYLE, t),
        "blockquote_open" => format!("<blockquote style=\"{BLOCKQUOTE_STYLE}\">"),
        "code_inline" => format!(
            "<code style=\"{CODE_STYLE}\">{}</code>",
            escape_html(&t.content)
        ),
        "fence" | "code_block" => format!(
            "<pre style=\"{PRE_STYLE}\"><code>{}</code></pre>\n",
            escape_html(&t.content)
        ),
        "image" => {
            let mut img = t.clone();
            let alt = render_inline_as_text(t.children.as_deref().unwrap_or(&[]));
            img.attr_set("alt", alt);
            render_token_with(tokens, idx, &img)
        }
        "hardbreak" => "<br />\n".into(),
        "softbreak" => "\n".into(),
        "text" => escape_html(&t.content),
        "html_block" | "html_inline" => t.content.clone(),
        _ => render_token(tokens, idx),
    }
}

/// `_td_rule`: the cell's GFM alignment kept after the base style.
fn cell(tag: &str, base: &str, t: &Token) -> String {
    match t.attr_get("style").filter(|a| !a.is_empty()) {
        Some(align) => format!("<{tag} style=\"{base};{align}\">"),
        None => format!("<{tag} style=\"{base}\">"),
    }
}

/// `renderInlineAsText` (an image's `alt`).
fn render_inline_as_text(tokens: &[Token]) -> String {
    let mut out = String::new();
    for t in tokens {
        match t.ty {
            "text" => out.push_str(&t.content),
            "image" => {
                if let Some(children) = t.children.as_deref() {
                    out.push_str(&render_inline_as_text(children));
                }
            }
            "softbreak" => out.push('\n'),
            _ => {}
        }
    }
    out
}

fn render_token(tokens: &[Token], idx: usize) -> String {
    render_token_with(tokens, idx, &tokens[idx])
}

/// `renderToken`, for `token` standing at `idx`.
fn render_token_with(tokens: &[Token], idx: usize, token: &Token) -> String {
    if token.hidden {
        return String::new();
    }
    let mut out = String::new();
    if token.block && token.nesting != -1 && idx > 0 && tokens[idx - 1].hidden {
        out.push('\n');
    }
    out.push_str(if token.nesting == -1 { "</" } else { "<" });
    out.push_str(token.tag);
    for (k, v) in &token.attrs {
        out.push(' ');
        out.push_str(&escape_html(k));
        out.push_str("=\"");
        out.push_str(&escape_html(v));
        out.push('"');
    }
    if token.nesting == 0 {
        out.push_str(" /");
    }
    let mut need_lf = false;
    if token.block {
        need_lf = true;
        if token.nesting == 1 {
            if let Some(next) = tokens.get(idx + 1) {
                if next.ty == "inline"
                    || next.hidden
                    || (next.nesting == -1 && next.tag == token.tag)
                {
                    need_lf = false;
                }
            }
        }
    }
    out.push_str(if need_lf { ">\n" } else { ">" });
    out
}
