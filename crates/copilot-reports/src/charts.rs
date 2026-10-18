//! The report charts (`incidents/services/customer_report_charts.py`), drawn
//! in Rust: the same donut, horizontal bar, monthly evolution and line
//! charts from the same data, laid out after matplotlib's (150 dpi, the
//! module's colours, sizes and fonts — DejaVu Sans, read from the system),
//! but not matplotlib's pixels (a §4 row).
//!
//! Each PNG carries the call that drew it — the function's name and its
//! arguments as the Python call site passes them — base64-encoded JSON in a
//! `tEXt` chunk named [`ARGS_KEYWORD`], so the parity suite can compare what
//! the two backends charted.

use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

/// The `tEXt` keyword of a chart's call.
pub const ARGS_KEYWORD: &str = "copilot-chart";
/// The directory the fonts are read from instead of the system's.
pub const FONT_DIR_OVERRIDE: &str = "COPILOT_REPORT_FONT_DIR";

const DPI: f32 = 150.0;
const PT: f32 = DPI / 72.0;

/// `PALETTE`.
pub const PALETTE: [&str; 10] = [
    "#f5c518", "#ee4b3b", "#4fa8e0", "#2ecc71", "#8c6fe0", "#1a1a1a", "#f5842b", "#22c1dc",
    "#ec4899", "#84cc16",
];
const STATUS_COLORS: [(&str, &str); 8] = [
    ("OPEN", "#f5c518"),
    ("IN_PROGRESS", "#4fa8e0"),
    ("IN PROGRESS", "#4fa8e0"),
    ("CLOSED", "#2ecc71"),
    ("PENDING_CUSTOMER", "#a78bfa"),
    ("RESOLVED", "#2ecc71"),
    ("ESCALATED", "#ee4b3b"),
    ("FALSE_POSITIVE", "#94a3b8"),
];
const BAR_FILL: &str = "#8c93e8";
const EVO_FILL: &str = "#7c6fd6";
const TEXT: &str = "#1e293b";
const MUTED: &str = "#475569";
const PLOT_BG: &str = "#eaeaf2";
const GRID: &str = "#e2e8f0";
const LEADER: &str = "#94a3b8";
const EMPTY_MSG: &str = "No data for this period";

// ------------------------------------------------------------------ fonts

struct Fonts {
    regular: Option<Vec<u8>>,
    bold: Option<Vec<u8>>,
}

fn fonts() -> &'static Fonts {
    static F: OnceLock<Fonts> = OnceLock::new();
    F.get_or_init(|| {
        let mut dirs = Vec::new();
        if let Some(d) = std::env::var_os(FONT_DIR_OVERRIDE) {
            dirs.push(std::path::PathBuf::from(d));
        }
        dirs.push("/usr/share/fonts/truetype/dejavu".into());
        dirs.push("/usr/share/fonts/dejavu".into());
        let load = |name: &str| {
            dirs.iter()
                .find_map(|d| std::fs::read(d.join(name)).ok())
                .filter(|b| ttf_parser::Face::parse(b, 0).is_ok())
        };
        let regular = load("DejaVuSans.ttf");
        let bold = load("DejaVuSans-Bold.ttf").or_else(|| regular.clone());
        if regular.is_none() {
            tracing::warn!("DejaVu Sans not found: the report charts are drawn without text");
        }
        Fonts { regular, bold }
    })
}

// ---------------------------------------------------------------- canvas

#[derive(Clone, Copy)]
struct Rgb(f32, f32, f32);

fn rgb(hex: &str) -> Rgb {
    let h = hex.trim_start_matches('#');
    let p = |i: usize| u8::from_str_radix(h.get(i..i + 2).unwrap_or("00"), 16).unwrap_or(0);
    Rgb(
        f32::from(p(0)) / 255.0,
        f32::from(p(2)) / 255.0,
        f32::from(p(4)) / 255.0,
    )
}

/// A white RGB canvas with coverage-accumulating anti-aliased fills.
struct Canvas {
    w: usize,
    h: usize,
    px: Vec<Rgb>,
}

type Contour = Vec<(f32, f32)>;

impl Canvas {
    fn new(w: usize, h: usize) -> Self {
        Self {
            w: w.max(1),
            h: h.max(1),
            px: vec![Rgb(1.0, 1.0, 1.0); w.max(1) * h.max(1)],
        }
    }

    /// Fill closed contours (non-zero, signed-area accumulation).
    fn fill(&mut self, contours: &[Contour], color: Rgb) {
        let (w, h) = (self.w, self.h);
        let stride = w + 2;
        let mut acc = vec![0f32; stride * h + 2];
        let clamp = |p: (f32, f32)| (p.0.clamp(0.0, w as f32), p.1.clamp(0.0, h as f32));
        for c in contours {
            if c.len() < 2 {
                continue;
            }
            for i in 0..c.len() {
                let a = clamp(c[i]);
                let b = clamp(c[(i + 1) % c.len()]);
                line(&mut acc, stride, h, a, b);
            }
        }
        for y in 0..h {
            let mut sum = 0f32;
            for x in 0..w {
                sum += acc[y * stride + x];
                let cov = sum.abs().min(1.0);
                if cov > 0.001 {
                    let p = &mut self.px[y * w + x];
                    p.0 += (color.0 - p.0) * cov;
                    p.1 += (color.1 - p.1) * cov;
                    p.2 += (color.2 - p.2) * cov;
                }
            }
        }
    }

    /// A polyline stroked with butt ends (each segment its own quad).
    fn stroke(&mut self, pts: &[(f32, f32)], width: f32, color: Rgb) {
        let mut quads = Vec::new();
        for seg in pts.windows(2) {
            let (a, b) = (seg[0], seg[1]);
            let (dx, dy) = (b.0 - a.0, b.1 - a.1);
            let len = (dx * dx + dy * dy).sqrt();
            if len < 1e-3 {
                continue;
            }
            let (nx, ny) = (-dy / len * width / 2.0, dx / len * width / 2.0);
            quads.push(vec![
                (a.0 + nx, a.1 + ny),
                (b.0 + nx, b.1 + ny),
                (b.0 - nx, b.1 - ny),
                (a.0 - nx, a.1 - ny),
            ]);
        }
        for q in quads {
            self.fill(&[q], color);
        }
    }

    fn dashed(&mut self, a: (f32, f32), b: (f32, f32), width: f32, on: f32, off: f32, c: Rgb) {
        let (dx, dy) = (b.0 - a.0, b.1 - a.1);
        let len = (dx * dx + dy * dy).sqrt();
        let mut t = 0.0;
        while t < len {
            let e = (t + on).min(len);
            let p = |s: f32| (a.0 + dx * s / len, a.1 + dy * s / len);
            self.stroke(&[p(t), p(e)], width, c);
            t = e + off;
        }
    }

    fn circle(&mut self, cx: f32, cy: f32, r: f32, color: Rgb) {
        let n = 24;
        let c: Contour = (0..n)
            .map(|i| {
                let a = i as f32 / n as f32 * std::f32::consts::TAU;
                (cx + r * a.cos(), cy + r * a.sin())
            })
            .collect();
        self.fill(&[c], color);
    }

    /// Text with its anchor at `(x, y)` (`ha`: 0 left, 0.5 centre, 1 right;
    /// `va`: 0 top, 0.5 centre, 1 bottom), lines 1.2 em apart.
    fn text(&mut self, t: &Text, x: f32, y: f32, ha: f32, va: f32, color: Rgb) {
        let Some(face) = t.face() else { return };
        let (w, h) = t.size();
        let top = y - h * va;
        let line_h = t.px * 1.2;
        let scale = t.px / f32::from(face.units_per_em());
        let ascent = f32::from(face.ascender()) * scale;
        let descent = -f32::from(face.descender()) * scale;
        let pad = (line_h - ascent - descent) / 2.0;
        for (i, line) in t.text.split('\n').enumerate() {
            let lw = advance(&face, line, scale);
            let mut pen = x - w * ha + (w - lw) * ha;
            let base = top + i as f32 * line_h + pad + ascent;
            let mut contours = Vec::new();
            for ch in line.chars() {
                let Some(id) = face.glyph_index(ch) else {
                    pen += t.px * 0.5;
                    continue;
                };
                let mut b = Outline {
                    contours: Vec::new(),
                    cur: Vec::new(),
                    x: pen,
                    y: base,
                    scale,
                    last: (0.0, 0.0),
                };
                face.outline_glyph(id, &mut b);
                b.flush();
                contours.extend(b.contours);
                pen += f32::from(face.glyph_hor_advance(id).unwrap_or(0)) * scale;
            }
            self.fill(&contours, color);
        }
    }

    fn png(&self, args: &Value) -> Vec<u8> {
        let mut raw = Vec::with_capacity((self.w * 3 + 1) * self.h);
        for y in 0..self.h {
            raw.push(0);
            for x in 0..self.w {
                let p = self.px[y * self.w + x];
                for c in [p.0, p.1, p.2] {
                    raw.push((c.clamp(0.0, 1.0) * 255.0).round() as u8);
                }
            }
        }
        let mut ihdr = Vec::with_capacity(13);
        ihdr.extend_from_slice(&(self.w as u32).to_be_bytes());
        ihdr.extend_from_slice(&(self.h as u32).to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        chunk(&mut png, b"IHDR", &ihdr);
        let mut text = ARGS_KEYWORD.as_bytes().to_vec();
        text.push(0);
        text.extend_from_slice(STANDARD.encode(args.to_string()).as_bytes());
        chunk(&mut png, b"tEXt", &text);
        chunk(
            &mut png,
            b"IDAT",
            &miniz_oxide::deflate::compress_to_vec_zlib(&raw, 6),
        );
        chunk(&mut png, b"IEND", &[]);
        png
    }
}

fn chunk(png: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    png.extend_from_slice(&(data.len() as u32).to_be_bytes());
    png.extend_from_slice(kind);
    png.extend_from_slice(data);
    let mut h = crc32fast::Hasher::new();
    h.update(kind);
    h.update(data);
    png.extend_from_slice(&h.finalize().to_be_bytes());
}

/// font-rs's line accumulation.
fn line(acc: &mut [f32], stride: usize, h: usize, p0: (f32, f32), p1: (f32, f32)) {
    if (p0.1 - p1.1).abs() <= f32::EPSILON {
        return;
    }
    let (dir, p0, p1) = if p0.1 < p1.1 {
        (1.0, p0, p1)
    } else {
        (-1.0, p1, p0)
    };
    let dxdy = (p1.0 - p0.0) / (p1.1 - p0.1);
    let mut x = p0.0;
    let y0 = p0.1.max(0.0) as usize;
    let mut add = |i: usize, v: f32| {
        if let Some(slot) = acc.get_mut(i) {
            *slot += v;
        }
    };
    for y in y0..h.min(p1.1.ceil() as usize) {
        let ls = y * stride;
        let dy = ((y + 1) as f32).min(p1.1) - (y as f32).max(p0.1);
        let xnext = x + dxdy * dy;
        let d = dy * dir;
        let (x0, x1) = if x < xnext { (x, xnext) } else { (xnext, x) };
        let x0f = x0.floor();
        let x0i = x0f as usize;
        let x1c = x1.ceil();
        let x1i = x1c as usize;
        if x1i <= x0i + 1 {
            let xmf = 0.5 * (x + xnext) - x0f;
            add(ls + x0i, d - d * xmf);
            add(ls + x0i + 1, d * xmf);
        } else {
            let s = (x1 - x0).recip();
            let x0frac = x0 - x0f;
            let a0 = 0.5 * s * (1.0 - x0frac) * (1.0 - x0frac);
            let x1frac = x1 - x1c + 1.0;
            let am = 0.5 * s * x1frac * x1frac;
            add(ls + x0i, d * a0);
            if x1i == x0i + 2 {
                add(ls + x0i + 1, d * (1.0 - a0 - am));
            } else {
                let a1 = s * (1.5 - x0frac);
                add(ls + x0i + 1, d * (a1 - a0));
                for xi in x0i + 2..x1i - 1 {
                    add(ls + xi, d * s);
                }
                let a2 = a1 + (x1i - x0i - 3) as f32 * s;
                add(ls + x1i - 1, d * (1.0 - a2 - am));
            }
            add(ls + x1i, d * am);
        }
        x = xnext;
    }
}

struct Outline {
    contours: Vec<Contour>,
    cur: Contour,
    x: f32,
    y: f32,
    scale: f32,
    last: (f32, f32),
}

impl Outline {
    fn pt(&self, x: f32, y: f32) -> (f32, f32) {
        (self.x + x * self.scale, self.y - y * self.scale)
    }

    fn flush(&mut self) {
        if self.cur.len() > 1 {
            self.contours.push(std::mem::take(&mut self.cur));
        }
        self.cur.clear();
    }
}

impl ttf_parser::OutlineBuilder for Outline {
    fn move_to(&mut self, x: f32, y: f32) {
        self.flush();
        let p = self.pt(x, y);
        self.cur.push(p);
        self.last = p;
    }
    fn line_to(&mut self, x: f32, y: f32) {
        let p = self.pt(x, y);
        self.cur.push(p);
        self.last = p;
    }
    fn quad_to(&mut self, x1: f32, y1: f32, x: f32, y: f32) {
        let (c, p) = (self.pt(x1, y1), self.pt(x, y));
        let s = self.last;
        for i in 1..=6 {
            let t = i as f32 / 6.0;
            let u = 1.0 - t;
            self.cur.push((
                u * u * s.0 + 2.0 * u * t * c.0 + t * t * p.0,
                u * u * s.1 + 2.0 * u * t * c.1 + t * t * p.1,
            ));
        }
        self.last = p;
    }
    fn curve_to(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, x: f32, y: f32) {
        let (c1, c2, p) = (self.pt(x1, y1), self.pt(x2, y2), self.pt(x, y));
        let s = self.last;
        for i in 1..=8 {
            let t = i as f32 / 8.0;
            let u = 1.0 - t;
            self.cur.push((
                u * u * u * s.0 + 3.0 * u * u * t * c1.0 + 3.0 * u * t * t * c2.0 + t * t * t * p.0,
                u * u * u * s.1 + 3.0 * u * u * t * c1.1 + 3.0 * u * t * t * c2.1 + t * t * t * p.1,
            ));
        }
        self.last = p;
    }
    fn close(&mut self) {
        self.flush();
    }
}

fn advance(face: &ttf_parser::Face<'_>, line: &str, scale: f32) -> f32 {
    line.chars()
        .map(|ch| {
            face.glyph_index(ch)
                .and_then(|id| face.glyph_hor_advance(id))
                .map_or(face.units_per_em() as f32 * 0.5, f32::from)
                * scale
        })
        .sum()
}

/// A piece of text at a point size.
struct Text {
    text: String,
    px: f32,
    bold: bool,
}

impl Text {
    fn new(text: impl Into<String>, pt: f32, bold: bool) -> Self {
        Self {
            text: text.into(),
            px: pt * PT,
            bold,
        }
    }

    fn face(&self) -> Option<ttf_parser::Face<'static>> {
        let f = fonts();
        let data = if self.bold { &f.bold } else { &f.regular };
        data.as_deref()
            .and_then(|d| ttf_parser::Face::parse(d, 0).ok())
    }

    /// Width and height in pixels.
    fn size(&self) -> (f32, f32) {
        let lines = self.text.split('\n').count().max(1) as f32;
        let h = self.px * 1.2 * lines;
        let w = match self.face() {
            Some(face) => {
                let scale = self.px / f32::from(face.units_per_em());
                self.text
                    .split('\n')
                    .map(|l| advance(&face, l, scale))
                    .fold(0.0, f32::max)
            }
            None => self.text.chars().count() as f32 * self.px * 0.55,
        };
        (w, h)
    }
}

/// Drawing commands in figure pixels, laid out before the canvas is sized
/// (matplotlib's `bbox_inches="tight"`: the drawn extent plus 0.1 in).
enum Cmd {
    Fill(Vec<Contour>, Rgb),
    Stroke(Vec<(f32, f32)>, f32, Rgb),
    Dashed((f32, f32), (f32, f32), f32, Rgb),
    Circle(f32, f32, f32, Rgb),
    Text(Text, f32, f32, f32, f32, Rgb),
}

#[derive(Default)]
struct Scene {
    cmds: Vec<Cmd>,
    min: (f32, f32),
    max: (f32, f32),
    any: bool,
}

impl Scene {
    fn grow(&mut self, x: f32, y: f32) {
        if !self.any {
            self.min = (x, y);
            self.max = (x, y);
            self.any = true;
        }
        self.min = (self.min.0.min(x), self.min.1.min(y));
        self.max = (self.max.0.max(x), self.max.1.max(y));
    }

    fn fill(&mut self, c: Vec<Contour>, color: Rgb) {
        for p in c.iter().flatten() {
            self.grow(p.0, p.1);
        }
        self.cmds.push(Cmd::Fill(c, color));
    }

    fn rect(&mut self, x0: f32, y0: f32, x1: f32, y1: f32, color: Rgb) {
        self.fill(vec![vec![(x0, y0), (x1, y0), (x1, y1), (x0, y1)]], color);
    }

    fn stroke(&mut self, pts: Vec<(f32, f32)>, width: f32, color: Rgb) {
        for p in &pts {
            self.grow(p.0, p.1);
        }
        self.cmds.push(Cmd::Stroke(pts, width, color));
    }

    fn text(&mut self, t: Text, x: f32, y: f32, ha: f32, va: f32, color: Rgb) {
        let (w, h) = t.size();
        self.grow(x - w * ha, y - h * va);
        self.grow(x - w * ha + w, y - h * va + h);
        self.cmds.push(Cmd::Text(t, x, y, ha, va, color));
    }

    fn render(self, args: &Value) -> Vec<u8> {
        let pad = 0.1 * DPI;
        let (ox, oy) = (self.min.0 - pad, self.min.1 - pad);
        let w = (self.max.0 - self.min.0 + 2.0 * pad).ceil().max(1.0) as usize;
        let h = (self.max.1 - self.min.1 + 2.0 * pad).ceil().max(1.0) as usize;
        let mut c = Canvas::new(w, h);
        let m = |p: (f32, f32)| (p.0 - ox, p.1 - oy);
        for cmd in self.cmds {
            match cmd {
                Cmd::Fill(cs, color) => {
                    let cs: Vec<Contour> = cs
                        .into_iter()
                        .map(|c| c.into_iter().map(m).collect())
                        .collect();
                    c.fill(&cs, color);
                }
                Cmd::Stroke(pts, width, color) => {
                    let pts: Vec<(f32, f32)> = pts.into_iter().map(m).collect();
                    c.stroke(&pts, width, color);
                }
                Cmd::Dashed(a, b, width, color) => {
                    c.dashed(m(a), m(b), width, 4.0 * PT, 3.0 * PT, color)
                }
                Cmd::Circle(x, y, r, color) => {
                    let p = m((x, y));
                    c.circle(p.0, p.1, r, color);
                }
                Cmd::Text(t, x, y, ha, va, color) => {
                    let p = m((x, y));
                    c.text(&t, p.0, p.1, ha, va, color);
                }
            }
        }
        c.png(args)
    }
}

fn data_uri(png: &[u8]) -> String {
    format!("data:image/png;base64,{}", STANDARD.encode(png))
}

/// matplotlib's figure subplot box in pixels: left, top, right, bottom.
fn axes_box(w_in: f32, h_in: f32) -> (f32, f32, f32, f32) {
    let (w, h) = (w_in * DPI, h_in * DPI);
    (0.125 * w, 0.12 * h, 0.9 * w, 0.89 * h)
}

/// `MaxNLocator(integer=True)`-like ticks over `[lo, hi]`.
fn int_ticks(lo: f64, hi: f64) -> Vec<f64> {
    let span = (hi - lo).max(1.0);
    let mut step = 1.0;
    'outer: for mag in 0..12 {
        for m in [1.0, 2.0, 2.5, 5.0] {
            let s: f64 = m * 10f64.powi(mag);
            if s.fract() != 0.0 {
                continue;
            }
            if span / s <= 9.0 {
                step = s;
                break 'outer;
            }
        }
    }
    let mut out = Vec::new();
    let mut v = (lo / step).ceil() * step;
    while v <= hi + 1e-9 {
        out.push(v);
        v += step;
    }
    out
}

fn tick_label(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{}", v as i64)
    } else {
        copilot_jinja::float_repr(v)
    }
}

/// `_empty(width_in, height_in)`.
fn empty(args: &Value) -> String {
    let mut s = Scene::default();
    s.text(
        Text::new(EMPTY_MSG, 12.0, false),
        0.0,
        0.0,
        0.5,
        0.5,
        rgb(MUTED),
    );
    data_uri(&s.render(args))
}

fn colors_for(labels: &[String], status_aware: bool) -> Vec<String> {
    labels
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let fallback = PALETTE[i % PALETTE.len()];
            if status_aware {
                let up = label.to_uppercase();
                STATUS_COLORS
                    .iter()
                    .find(|(k, _)| *k == up)
                    .map_or(fallback, |(_, c)| c)
                    .to_string()
            } else {
                fallback.to_string()
            }
        })
        .collect()
}

fn pairs_json(data: &[(String, i64)]) -> Value {
    Value::Array(data.iter().map(|(l, v)| json!([l, v])).collect())
}

/// `donut_png(data, status_aware=…)`.
pub fn donut_png(data: &[(String, i64)], status_aware: bool) -> String {
    let args = if status_aware {
        json!({"chart": "donut_png", "args": [pairs_json(data)], "kwargs": {"status_aware": true}})
    } else {
        json!({"chart": "donut_png", "args": [pairs_json(data)], "kwargs": {}})
    };
    let data: Vec<(String, i64)> = data.iter().filter(|(_, v)| *v > 0).cloned().collect();
    if data.is_empty() {
        return empty(&args);
    }
    let labels: Vec<String> = data.iter().map(|d| d.0.clone()).collect();
    let total: i64 = data.iter().map(|d| d.1).sum();
    let colors = colors_for(&labels, status_aware);
    // Equal aspect over x in [-1.7, 1.7], y in [-1.5, 1.5] inside the axes.
    let (l, t, r, b) = axes_box(5.2, 3.2);
    let unit = ((r - l) / 3.4).min((b - t) / 3.0);
    let (cx, cy) = ((l + r) / 2.0, (t + b) / 2.0);
    let at = |x: f64, y: f64| (cx + x as f32 * unit, cy - y as f32 * unit);
    let mut s = Scene::default();
    let mut theta = 90.0f64;
    let mut placements = Vec::new();
    for (i, (label, value)) in data.iter().enumerate() {
        let sweep = *value as f64 / total as f64 * 360.0;
        let (t1, t2) = (theta - sweep, theta);
        let n = ((sweep / 3.0).ceil() as usize).max(2);
        let mut contour = Vec::new();
        for k in 0..=n {
            let a = (t2 - (t2 - t1) * k as f64 / n as f64).to_radians();
            contour.push(at(a.cos(), a.sin()));
        }
        for k in (0..=n).rev() {
            let a = (t2 - (t2 - t1) * k as f64 / n as f64).to_radians();
            contour.push(at(0.58 * a.cos(), 0.58 * a.sin()));
        }
        s.fill(vec![contour], rgb(&colors[i]));
        let mid = ((t1 + t2) / 2.0).to_radians();
        let (x, y) = (mid.cos(), mid.sin());
        placements.push((x, y, x >= 0.0, y * 1.32, label.clone(), *value));
        theta = t1;
    }
    // White wedge edges.
    let mut theta = 90.0f64;
    for (_, value) in &data {
        let a = theta.to_radians();
        s.stroke(
            vec![at(0.58 * a.cos(), 0.58 * a.sin()), at(a.cos(), a.sin())],
            1.5 * PT,
            rgb("#ffffff"),
        );
        theta -= *value as f64 / total as f64 * 360.0;
    }
    for side in [true, false] {
        let mut idx: Vec<usize> = (0..placements.len())
            .filter(|&i| placements[i].2 == side)
            .collect();
        idx.sort_by(|&a, &b| {
            placements[a]
                .3
                .partial_cmp(&placements[b].3)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for k in 1..idx.len() {
            if placements[idx[k]].3 - placements[idx[k - 1]].3 < 0.42 {
                placements[idx[k]].3 = placements[idx[k - 1]].3 + 0.42;
            }
        }
    }
    for (x, y, left, ty, label, value) in &placements {
        let tx = if *left { 1.34 } else { -1.34 };
        let pct = crate::sla::pyfmt(*value as f64 / total as f64 * 100.0, ".3g");
        let text = format!("{label}\n{value} ({pct}%)");
        s.stroke(
            vec![at(x * 0.98, y * 0.98), at(tx, *ty)],
            0.8 * PT,
            rgb(LEADER),
        );
        let (px, py) = at(tx, *ty);
        let ha = if *left { 0.0 } else { 1.0 };
        s.text(Text::new(text, 8.5, true), px, py, ha, 0.5, rgb(TEXT));
    }
    let (px, py) = at(0.0, 0.06);
    s.text(
        Text::new(total.to_string(), 17.0, true),
        px,
        py,
        0.5,
        0.5,
        rgb(TEXT),
    );
    let (px, py) = at(0.0, -0.16);
    s.text(Text::new("total", 9.0, false), px, py, 0.5, 0.5, rgb(MUTED));
    data_uri(&s.render(&args))
}

/// `hbar_png(data, color=…)`.
pub fn hbar_png(data: &[(String, i64)], color: Option<&str>) -> String {
    let args = json!({"chart": "hbar_png", "args": [pairs_json(data)], "kwargs": {"color": color}});
    if data.is_empty() {
        return empty(&args);
    }
    let rows: Vec<(String, i64)> = data.iter().rev().cloned().collect();
    let labels: Vec<String> = rows
        .iter()
        .map(|(l, _)| {
            if l.chars().count() <= 60 {
                l.clone()
            } else {
                format!("{}\u{2026}", l.chars().take(59).collect::<String>())
            }
        })
        .collect();
    let n = rows.len();
    let h_in = (0.34 * n as f32 + 0.6).max(1.4);
    let (l, t, r, b) = axes_box(8.4, h_in);
    let max_v = rows.iter().map(|r| r.1).max().unwrap_or(1).max(1) as f64;
    let xmax = max_v * 1.12;
    let span = (n as f64 - 1.0) + 0.68;
    let (ylo, yhi) = (-0.34 - 0.05 * span, n as f64 - 1.0 + 0.34 + 0.05 * span);
    let fx = |v: f64| l + ((v / xmax) as f32) * (r - l);
    let fy = |v: f64| b - (((v - ylo) / (yhi - ylo)) as f32) * (b - t);
    let fill = rgb(color.unwrap_or(BAR_FILL));
    let mut s = Scene::default();
    for tick in int_ticks(0.0, xmax) {
        let x = fx(tick);
        s.stroke(vec![(x, t), (x, b)], 0.8 * PT, rgb(GRID));
        s.text(
            Text::new(tick_label(tick), 8.0, false),
            x,
            t - 3.5 * PT,
            0.5,
            1.0,
            rgb(MUTED),
        );
    }
    for (i, ((_, v), label)) in rows.iter().zip(&labels).enumerate() {
        let (y0, y1) = (fy(i as f64 + 0.34), fy(i as f64 - 0.34));
        s.rect(fx(0.0), y0, fx(*v as f64), y1, fill);
        let yc = fy(i as f64);
        s.text(
            Text::new(label.clone(), 8.0, false),
            l - 3.5 * PT,
            yc,
            1.0,
            0.5,
            rgb(TEXT),
        );
        s.text(
            Text::new(v.to_string(), 8.0, true),
            fx(*v as f64 + max_v * 0.01),
            yc,
            0.0,
            0.5,
            rgb(TEXT),
        );
    }
    data_uri(&s.render(&args))
}

/// `evolution_png(months, values, color=…)`.
pub fn evolution_png(months: &[String], values: &[i64], color: Option<&str>) -> String {
    let args =
        json!({"chart": "evolution_png", "args": [months, values], "kwargs": {"color": color}});
    if months.is_empty() || values.is_empty() {
        return empty(&args);
    }
    let (l, t, r, b) = axes_box(6.4, 3.0);
    let n = values.len();
    let max_v = values.iter().copied().max().unwrap_or(1) as f64;
    let ymax = if max_v != 0.0 { max_v * 1.16 } else { 1.0 };
    let span = (n as f64 - 1.0) + 0.62;
    let (xlo, xhi) = (-0.31 - 0.05 * span, n as f64 - 1.0 + 0.31 + 0.05 * span);
    let fx = |v: f64| l + (((v - xlo) / (xhi - xlo)) as f32) * (r - l);
    let fy = |v: f64| b - ((v / ymax) as f32) * (b - t);
    let mut s = Scene::default();
    s.rect(l, t, r, b, rgb(PLOT_BG));
    for tick in int_ticks(0.0, ymax) {
        let y = fy(tick);
        s.stroke(vec![(l, y), (r, y)], 1.1 * PT, rgb("#ffffff"));
        s.text(
            Text::new(tick_label(tick), 8.0, false),
            l - 3.5 * PT,
            y,
            1.0,
            0.5,
            rgb(MUTED),
        );
    }
    let fill = rgb(color.unwrap_or(EVO_FILL));
    for (i, (v, month)) in values.iter().zip(months).enumerate() {
        let x = i as f64;
        s.rect(fx(x - 0.31), fy(*v as f64), fx(x + 0.31), fy(0.0), fill);
        s.text(
            Text::new(v.to_string(), 8.0, true),
            fx(x),
            fy(*v as f64 + max_v * 0.02),
            0.5,
            1.0,
            rgb(TEXT),
        );
        s.text(
            Text::new(month.clone(), 8.0, false),
            fx(x),
            b + 3.5 * PT,
            0.5,
            0.0,
            rgb(MUTED),
        );
    }
    data_uri(&s.render(&args))
}

/// One series of [`line_png`]: name, values (`None` leaves a gap), colour.
pub type Series = (String, Vec<Option<f64>>, String);

fn series_json(series: &[Series]) -> Value {
    Value::Array(series.iter().map(|(n, v, c)| json!([n, v, c])).collect())
}

/// `line_png(labels, series, percent=…, reference=…)`; `kwargs` are the
/// keyword arguments the Python call site passes.
pub fn line_png(
    labels: &[String],
    series: &[Series],
    percent: bool,
    reference: Option<f64>,
) -> String {
    let mut kwargs = serde_json::Map::new();
    if percent {
        kwargs.insert("percent".into(), Value::Bool(true));
    }
    if let Some(r) = reference {
        kwargs.insert("reference".into(), json!(r));
    }
    let args =
        json!({"chart": "line_png", "args": [labels, series_json(series)], "kwargs": kwargs});
    if labels.is_empty() || !series.iter().any(|(_, v, _)| v.iter().any(Option::is_some)) {
        return empty(&args);
    }
    let (l, t, r, b) = axes_box(8.4, 2.6);
    let n = labels.len();
    let max_v = series
        .iter()
        .flat_map(|(_, v, _)| v.iter().flatten())
        .fold(0f64, |a, b| a.max(*b));
    let ymax = if percent {
        104.0
    } else {
        (max_v * 1.05).max(1.0)
    };
    let span = (n as f64 - 1.0).max(1.0);
    let (xlo, xhi) = (-0.05 * span, n as f64 - 1.0 + 0.05 * span);
    let fx = |v: f64| l + (((v - xlo) / (xhi - xlo)) as f32) * (r - l);
    let fy = |v: f64| b - ((v / ymax) as f32) * (b - t);
    let mut s = Scene::default();
    let ticks = if percent {
        (0..=5).map(|i| f64::from(i) * 20.0).collect()
    } else {
        int_ticks(0.0, ymax)
    };
    for tick in ticks {
        let y = fy(tick);
        s.stroke(vec![(l, y), (r, y)], 0.8 * PT, rgb(GRID));
        let label = if percent {
            format!("{}%", crate::sla::pyfmt(tick, ".0f"))
        } else {
            tick_label(tick)
        };
        s.text(
            Text::new(label, 7.5, false),
            l - 3.5 * PT,
            y,
            1.0,
            0.5,
            rgb(MUTED),
        );
    }
    if let Some(reference) = reference {
        let y = fy(reference);
        s.cmds
            .push(Cmd::Dashed((l, y), (r, y), 0.9 * PT, rgb(LEADER)));
    }
    let step = n.div_ceil(12).max(1);
    for i in (0..n).step_by(step) {
        s.text(
            Text::new(labels[i].clone(), 7.5, false),
            fx(i as f64),
            b + 3.5 * PT,
            0.5,
            0.0,
            rgb(MUTED),
        );
    }
    for (_, values, color) in series {
        let c = rgb(color);
        let mut run: Vec<(f32, f32)> = Vec::new();
        for (i, v) in values.iter().enumerate() {
            match v {
                Some(v) => {
                    let p = (fx(i as f64), fy(*v));
                    run.push(p);
                    s.cmds.push(Cmd::Circle(p.0, p.1, 1.5 * PT, c));
                }
                None => {
                    if run.len() > 1 {
                        s.stroke(std::mem::take(&mut run), 1.8 * PT, c);
                    }
                    run.clear();
                }
            }
        }
        if run.len() > 1 {
            s.stroke(run, 1.8 * PT, c);
        }
    }
    if series.len() > 1 {
        let mut x = l + 6.0 * PT;
        let y = t + 8.0 * PT;
        for (name, _, color) in series {
            s.stroke(vec![(x, y), (x + 14.0 * PT, y)], 1.8 * PT, rgb(color));
            let label = Text::new(name.clone(), 7.5, false);
            let w = label.size().0;
            s.text(label, x + 18.0 * PT, y, 0.0, 0.5, rgb(MUTED));
            x += 18.0 * PT + w + 12.0 * PT;
        }
    }
    data_uri(&s.render(&args))
}

/// The call recorded in a chart's PNG (for tests and the parity suite).
pub fn recorded_args(uri: &str) -> Option<Value> {
    let b64 = uri.strip_prefix("data:image/png;base64,")?;
    let png = STANDARD.decode(b64).ok()?;
    let mut i = 8;
    while i + 8 <= png.len() {
        let len = u32::from_be_bytes(png[i..i + 4].try_into().ok()?) as usize;
        let kind = png.get(i + 4..i + 8)?;
        let data = png.get(i + 8..i + 8 + len)?;
        if kind == b"tEXt" {
            let mut parts = data.splitn(2, |&b| b == 0);
            if parts.next()? == ARGS_KEYWORD.as_bytes() {
                let raw = STANDARD.decode(parts.next()?).ok()?;
                return serde_json::from_slice(&raw).ok();
            }
        }
        i += 12 + len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `COPILOT_CHART_DUMP=dir cargo test … dumps_samples` writes sample PNGs.
    #[test]
    fn dumps_samples() {
        let Some(dir) = std::env::var_os("COPILOT_CHART_DUMP") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let png = |uri: String| {
            STANDARD
                .decode(uri.trim_start_matches("data:image/png;base64,"))
                .unwrap()
        };
        let d = vec![
            ("OPEN".to_string(), 12),
            ("CLOSED".to_string(), 30),
            ("IN_PROGRESS".to_string(), 5),
            ("PENDING_CUSTOMER".to_string(), 1),
        ];
        std::fs::write(dir.join("donut.png"), png(donut_png(&d, true))).unwrap();
        let bars: Vec<(String, i64)> = (0..8)
            .map(|i| {
                (
                    format!("Alert title number {i} with some words"),
                    40 - i * 4,
                )
            })
            .collect();
        std::fs::write(dir.join("hbar.png"), png(hbar_png(&bars, Some("#fc862e")))).unwrap();
        let months: Vec<String> = ["2026-01", "2026-02", "2026-03", "2026-04"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        std::fs::write(
            dir.join("evo.png"),
            png(evolution_png(&months, &[10, 25, 7, 18], Some("#fc862e"))),
        )
        .unwrap();
        let labels: Vec<String> = (1..=14).map(|i| format!("{i:02} Mar")).collect();
        let a: Vec<Option<f64>> = (0..14).map(|i| Some(f64::from(i * 3 % 11))).collect();
        let b: Vec<Option<f64>> = (0..14)
            .map(|i| {
                if i == 5 {
                    None
                } else {
                    Some(f64::from(i * 2 % 7))
                }
            })
            .collect();
        std::fs::write(
            dir.join("line.png"),
            png(line_png(
                &labels,
                &[
                    ("Alerts opened".into(), a, "#fc862e".into()),
                    ("Alerts resolved".into(), b, "#94a3b8".into()),
                ],
                false,
                None,
            )),
        )
        .unwrap();
        let p: Vec<Option<f64>> = (0..14)
            .map(|i| {
                if i % 4 == 0 {
                    None
                } else {
                    Some(80.0 + f64::from(i))
                }
            })
            .collect();
        std::fs::write(
            dir.join("line_pct.png"),
            png(line_png(
                &labels,
                &[("Resolve SLA met".into(), p, "#fc862e".into())],
                true,
                Some(95.0),
            )),
        )
        .unwrap();
        std::fs::write(dir.join("empty.png"), png(donut_png(&[], false))).unwrap();
    }

    #[test]
    fn charts_carry_their_call() {
        let d = vec![("OPEN".to_string(), 3), ("CLOSED".to_string(), 1)];
        let uri = donut_png(&d, true);
        assert_eq!(
            recorded_args(&uri).unwrap(),
            json!({"chart": "donut_png", "args": [[["OPEN", 3], ["CLOSED", 1]]], "kwargs": {"status_aware": true}})
        );
        let uri = hbar_png(&d, Some("#fc862e"));
        assert_eq!(recorded_args(&uri).unwrap()["kwargs"]["color"], "#fc862e");
        let uri = evolution_png(&["2026-01".into(), "2026-02".into()], &[3, 0], None);
        assert_eq!(recorded_args(&uri).unwrap()["args"][1], json!([3, 0]));
        let uri = line_png(
            &["a".into(), "b".into()],
            &[("x".into(), vec![Some(1.0), None], "#000000".into())],
            true,
            Some(95.0),
        );
        assert_eq!(
            recorded_args(&uri).unwrap()["kwargs"]["reference"],
            json!(95.0)
        );
        let uri = donut_png(&[], false);
        assert!(recorded_args(&uri).is_some());
    }
}
