//! Form bodies — Starlette's `Request.form()` (`starlette/formparsers.py`)
//! over python-multipart's parsers, as FastAPI calls it for `Form(...)`
//! parameters.
//!
//! Only `application/x-www-form-urlencoded` and `multipart/form-data` are
//! forms; any other (or no) Content-Type is an empty form. The quirks are
//! Python's and are kept on purpose:
//!
//! - the Content-Type is compared after python-multipart's
//!   `parse_options_header`, which lowercases it only when it carries no
//!   parameters (`Multipart/Form-Data; boundary=x` is not a form);
//! - urlencoded fields split on `&`, or on `;` only when no `&` follows;
//!   names and values are latin-1 text run through `unquote_plus`;
//! - a multipart part that is never closed is dropped, an unknown charset
//!   decodes as latin-1, and a value that is not valid in its charset too;
//! - malformed multipart framing is FastAPI's 400 "There was an error parsing
//!   the body", Starlette's own limits (`name` missing, 1 MB per field, 1000
//!   fields/files) are a 400 with Starlette's message.
//!
//! `form_vectors.json` (generated from Starlette and python-multipart) pins
//! the parsers. Bodies are parsed whole, not in the server's chunks: framing
//! that only fails across a chunk boundary is out of scope.

/// One form value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormValue {
    /// A field.
    Text(String),
    /// A file part (`UploadFile`); only its name is kept.
    File {
        /// The part's `filename`.
        filename: String,
    },
}

/// The parsed form, in body order (a key may repeat).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FormData(pub Vec<(String, FormValue)>);

impl FormData {
    /// `FormData.get(key)`: the *last* value for `key`.
    pub fn get(&self, key: &str) -> Option<&FormValue> {
        self.0.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}

/// Why a form could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormError {
    /// Starlette's `MultiPartException`: a 400 carrying this message.
    Rejected(String),
    /// Any other parser failure: FastAPI's 400 "There was an error parsing
    /// the body".
    Malformed,
}

/// Python's `str.isspace()`: Unicode White_Space plus the C0 separators.
pub fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python's `str.strip()`.
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

/// Bytes as latin-1 text (each byte one character).
pub fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// latin-1 text back to bytes (characters above U+00FF cannot occur in text
/// built by [`latin1`]; they are dropped).
fn latin1_bytes(s: &str) -> Vec<u8> {
    s.chars().filter_map(|c| u8::try_from(c).ok()).collect()
}

// ---------------------------------------------------------------------------
// parse_options_header (email.message's parameter parsing)
// ---------------------------------------------------------------------------

/// `email.message._parseparam`.
fn parse_params(value: &str) -> Vec<String> {
    let mut s: Vec<char> = std::iter::once(';').chain(value.chars()).collect();
    let mut out = Vec::new();
    let count = |s: &[char], end: usize, pat: &[char]| -> usize {
        let mut n = 0;
        let mut i = 0;
        while i + pat.len() <= end {
            if s[i..i + pat.len()] == *pat {
                n += 1;
                i += pat.len();
            } else {
                i += 1;
            }
        }
        n
    };
    let find = |s: &[char], from: usize| {
        s.iter()
            .skip(from)
            .position(|&c| c == ';')
            .map(|p| p + from)
    };
    while s.first() == Some(&';') {
        s.remove(0);
        let mut end = find(&s, 0);
        while let Some(e) = end.filter(|&e| e > 0) {
            if (count(&s, e, &['"']) - count(&s, e, &['\\', '"'])) % 2 == 0 {
                break;
            }
            end = find(&s, e + 1);
        }
        let end = end.unwrap_or(s.len());
        let f: String = s[..end].iter().collect();
        let f = match f.split_once('=') {
            Some((name, val)) => format!("{}={}", py_strip(name).to_lowercase(), py_strip(val)),
            None => f,
        };
        out.push(py_strip(&f).to_string());
        s.drain(..end);
    }
    out
}

/// `email.utils.unquote`.
fn email_unquote(s: &str) -> String {
    if s.chars().count() > 1 {
        if s.starts_with('"') && s.ends_with('"') {
            return s[1..s.len() - 1]
                .replace("\\\\", "\\")
                .replace("\\\"", "\"");
        }
        if s.starts_with('<') && s.ends_with('>') {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

/// `email.utils.quote`.
fn email_quote(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `^(\w+)\*((\d+)\*?)?$` (ASCII): an RFC 2231 parameter name.
fn rfc2231_name(name: &str) -> Option<(String, Option<u64>)> {
    let (base, rest) = name.split_once('*')?;
    if base.is_empty() || !base.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    if rest.is_empty() {
        return Some((base.to_string(), None));
    }
    let digits = rest.strip_suffix('*').unwrap_or(rest);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((base.to_string(), digits.parse().ok()))
}

/// One RFC 2231 segment: `(number, value, percent-encoded)`.
type Continuation = (Option<u64>, String, bool);

/// python-multipart's `parse_options_header`: the value and its parameters
/// (keys and values as latin-1 text; a repeated key keeps its first position
/// and its last value, like a dict). `None` is a Python exception (mixing
/// numbered and unnumbered RFC 2231 continuations).
pub fn parse_options_header(value: &str) -> Option<(String, Vec<(String, String)>)> {
    if value.is_empty() {
        return Some((String::new(), Vec::new()));
    }
    if !value.contains(';') {
        return Some((py_strip(&value.to_lowercase()).to_string(), Vec::new()));
    }
    let mut params = parse_params(value)
        .into_iter()
        .map(|p| match p.split_once('=') {
            Some((n, v)) => (py_strip(n).to_string(), py_strip(v).to_string()),
            None => (py_strip(&p).to_string(), String::new()),
        });
    let ctype = params.next().map(|(n, _)| n).unwrap_or_default();
    // email.utils.decode_params, then get_params' unquote.
    let mut decoded: Vec<(String, String)> = Vec::new();
    let mut continuations: Vec<(String, Vec<Continuation>)> = Vec::new();
    for (name, value) in params {
        let encoded = name.ends_with('*');
        let value = email_unquote(&value);
        match rfc2231_name(&name) {
            Some((base, num)) => match continuations.iter_mut().find(|(n, _)| *n == base) {
                Some((_, list)) => list.push((num, value, encoded)),
                None => continuations.push((base, vec![(num, value, encoded)])),
            },
            None => {
                let requoted = format!("\"{}\"", email_quote(&value));
                decoded.push((name, email_unquote(&requoted)));
            }
        }
    }
    for (name, mut parts) in continuations {
        let numbered = parts.iter().filter(|p| p.0.is_some()).count();
        if numbered != 0 && numbered != parts.len() {
            return None;
        }
        parts.sort();
        let mut extended = false;
        let mut joined = String::new();
        for (_, s, encoded) in parts {
            if encoded {
                joined.push_str(&unquote_with(&s, latin1));
                extended = true;
            } else {
                joined.push_str(&s);
            }
        }
        let quoted = email_quote(&joined);
        let value = if extended {
            match quoted.splitn(3, '\'').collect::<Vec<_>>().as_slice() {
                [_, _, v] => (*v).to_string(),
                _ => quoted.clone(),
            }
        } else {
            quoted
        };
        decoded.push((name, email_unquote(&format!("\"{value}\""))));
    }
    let mut options: Vec<(String, String)> = Vec::new();
    for (key, mut value) in decoded {
        if key == "filename" {
            let chars: Vec<char> = value.chars().collect();
            if chars.get(1..3) == Some(&[':', '\\'][..])
                || chars.get(..2) == Some(&['\\', '\\'][..])
            {
                value = value.rsplit('\\').next().unwrap_or_default().to_string();
            }
        }
        match options.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => *v = value,
            None => options.push((key, value)),
        }
    }
    Some((ctype, options))
}

fn option<'a>(options: &'a [(String, String)], key: &str) -> Option<&'a str> {
    options
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

// ---------------------------------------------------------------------------
// unquote_plus
// ---------------------------------------------------------------------------

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// `urllib.parse.unquote_to_bytes`.
fn unquote_to_bytes(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            if let (Some(h), Some(l)) = (
                s.get(i + 1).copied().and_then(hex),
                s.get(i + 2).copied().and_then(hex),
            ) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// `urllib.parse.unquote`: ASCII runs are percent-decoded and decoded with
/// `decode`; other characters pass through.
fn unquote_with(s: &str, decode: impl Fn(&[u8]) -> String) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let mut out = String::new();
    let mut run = String::new();
    for c in s.chars() {
        if c.is_ascii() {
            run.push(c);
        } else {
            if !run.is_empty() {
                out.push_str(&decode(&unquote_to_bytes(run.as_bytes())));
                run.clear();
            }
            out.push(c);
        }
    }
    if !run.is_empty() {
        out.push_str(&decode(&unquote_to_bytes(run.as_bytes())));
    }
    out
}

/// `urllib.parse.unquote_plus` (UTF-8, `errors="replace"`).
pub fn unquote_plus(s: &str) -> String {
    unquote_with(&s.replace('+', " "), |b| {
        String::from_utf8_lossy(b).into_owned()
    })
}

// ---------------------------------------------------------------------------
// application/x-www-form-urlencoded (QuerystringParser + FormParser)
// ---------------------------------------------------------------------------

fn find_byte(data: &[u8], b: u8, from: usize, to: usize) -> Option<usize> {
    data.get(from..to)?
        .iter()
        .position(|&x| x == b)
        .map(|p| p + from)
}

/// `FormParser.parse` over `QuerystringParser` (non-strict).
pub fn parse_urlencoded(data: &[u8]) -> Vec<(String, String)> {
    #[derive(PartialEq)]
    enum St {
        BeforeField,
        FieldName,
        FieldData,
    }
    let len = data.len();
    let mut items = Vec::new();
    let (mut name, mut value) = (Vec::new(), Vec::new());
    let end_field = |items: &mut Vec<(String, String)>, name: &[u8], value: &[u8]| {
        items.push((unquote_plus(&latin1(name)), unquote_plus(&latin1(value))));
    };
    let sep =
        |from: usize| find_byte(data, b'&', from, len).or_else(|| find_byte(data, b';', from, len));
    let mut state = St::BeforeField;
    let mut i = 0;
    while i < len {
        match state {
            St::BeforeField => {
                // Separators between fields are skipped (non-strict parsing).
                if data[i] != b'&' && data[i] != b';' {
                    name.clear();
                    value.clear();
                    state = St::FieldName;
                    continue;
                }
            }
            St::FieldName => {
                let sep_pos = sep(i);
                let equals = find_byte(data, b'=', i, sep_pos.unwrap_or(len));
                if let Some(eq) = equals {
                    name.extend_from_slice(&data[i..eq]);
                    i = eq;
                    state = St::FieldData;
                } else if let Some(sp) = sep_pos {
                    name.extend_from_slice(&data[i..sp]);
                    end_field(&mut items, &name, &value);
                    i = sp;
                    state = St::BeforeField;
                    continue;
                } else {
                    name.extend_from_slice(&data[i..]);
                    i = len;
                }
            }
            St::FieldData => match sep(i) {
                Some(sp) => {
                    value.extend_from_slice(&data[i..sp]);
                    end_field(&mut items, &name, &value);
                    i = sp;
                    state = St::BeforeField;
                    continue;
                }
                None => {
                    value.extend_from_slice(&data[i..]);
                    i = len;
                }
            },
        }
        i += 1;
    }
    if state != St::BeforeField {
        end_field(&mut items, &name, &value);
    }
    items
}

// ---------------------------------------------------------------------------
// multipart/form-data (MultipartParser + MultiPartParser)
// ---------------------------------------------------------------------------

const MAX_PART_SIZE: usize = 1024 * 1024;
const MAX_FIELDS: usize = 1000;
const MAX_FILES: usize = 1000;
const MAX_HEADER_COUNT: usize = 8;
const MAX_HEADER_SIZE: usize = 4096 + 128;
const CR: u8 = b'\r';
const LF: u8 = b'\n';
const HYPHEN: u8 = b'-';

fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// `_user_safe_decode`: the charset, else latin-1. Only the UTF-8 family is
/// decoded as such; ASCII and latin-1 give latin-1's result anyway, and other
/// codecs Python knows (cp1252, …) are read as latin-1 here.
fn safe_decode(bytes: &[u8], charset: &str) -> String {
    let mut norm = String::new();
    let mut punct = false;
    for c in charset.chars() {
        if c.is_alphanumeric() || c == '.' {
            if punct && !norm.is_empty() {
                norm.push('_');
            }
            if c.is_ascii() {
                norm.push(c.to_ascii_lowercase());
            }
            punct = false;
        } else {
            punct = true;
        }
    }
    let utf8 = matches!(
        norm.as_str(),
        "utf_8" | "utf8" | "u8" | "utf" | "utf8_ucs2" | "utf8_ucs4" | "cp65001"
    );
    if utf8 {
        if let Ok(s) = std::str::from_utf8(bytes) {
            return s.to_string();
        }
    }
    latin1(bytes)
}

#[derive(Default)]
struct Part {
    content_disposition: Option<Vec<u8>>,
    content_type: Option<Vec<u8>>,
    field_name: String,
    data_len: usize,
    file: Option<String>,
}

/// A file part's content, for the routes that read an `UploadFile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadPart {
    /// The form field (`name`).
    pub field: String,
    /// The part's `filename`.
    pub filename: String,
    /// `UploadFile.content_type`: the part's first `Content-Type`, as
    /// latin-1 text.
    pub content_type: Option<String>,
    /// The bytes.
    pub data: Vec<u8>,
}

/// Starlette's `MultiPartParser` callbacks.
struct Sink<'a> {
    charset: &'a str,
    items: Vec<(String, FormValue)>,
    keep_files: bool,
    uploads: Vec<UploadPart>,
    part: Part,
    header_name: Vec<u8>,
    header_value: Vec<u8>,
    fields: usize,
    files: usize,
}

impl Sink<'_> {
    fn part_data(&mut self, data: &[u8]) -> Result<(), FormError> {
        if self.part.file.is_none() {
            if self.part.data_len + data.len() > MAX_PART_SIZE {
                return Err(FormError::Rejected(format!(
                    "Part exceeded maximum size of {}KB.",
                    MAX_PART_SIZE / 1024
                )));
            }
            self.part.data_len += data.len();
        }
        Ok(())
    }

    fn part_end(&mut self, data: &[u8]) {
        let value = match self.part.file.take() {
            None => FormValue::Text(safe_decode(data, self.charset)),
            Some(filename) => {
                if self.keep_files {
                    self.uploads.push(UploadPart {
                        field: self.part.field_name.clone(),
                        filename: filename.clone(),
                        content_type: self.part.content_type.as_deref().map(latin1),
                        data: data.to_vec(),
                    });
                }
                FormValue::File { filename }
            }
        };
        self.part.content_type = None;
        self.items
            .push((std::mem::take(&mut self.part.field_name), value));
    }

    fn header_end(&mut self) {
        if self
            .header_name
            .eq_ignore_ascii_case(b"content-disposition")
        {
            self.part.content_disposition = Some(std::mem::take(&mut self.header_value));
        } else if self.header_name.eq_ignore_ascii_case(b"content-type")
            && self.part.content_type.is_none()
        {
            self.part.content_type = Some(std::mem::take(&mut self.header_value));
        }
        self.header_name.clear();
        self.header_value.clear();
    }

    fn headers_finished(&mut self) -> Result<(), FormError> {
        let cd = self
            .part
            .content_disposition
            .as_deref()
            .map(latin1)
            .unwrap_or_default();
        let (_, options) = parse_options_header(&cd).ok_or(FormError::Malformed)?;
        let name = option(&options, "name").ok_or_else(|| {
            FormError::Rejected(
                "The Content-Disposition header field \"name\" must be provided.".into(),
            )
        })?;
        self.part.field_name = safe_decode(&latin1_bytes(name), self.charset);
        if let Some(filename) = option(&options, "filename") {
            self.files += 1;
            if self.files > MAX_FILES {
                return Err(FormError::Rejected(format!(
                    "Too many files. Maximum number of files is {MAX_FILES}."
                )));
            }
            self.part.file = Some(safe_decode(&latin1_bytes(filename), self.charset));
        } else {
            self.fields += 1;
            if self.fields > MAX_FIELDS {
                return Err(FormError::Rejected(format!(
                    "Too many fields. Maximum number of fields is {MAX_FIELDS}."
                )));
            }
            self.part.file = None;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mp {
    Start,
    StartBoundary,
    HeaderFieldStart,
    HeaderField,
    HeaderValueStart,
    HeaderValue,
    HeaderValueAlmostDone,
    HeadersAlmostDone,
    PartDataStart,
    PartData,
    EndBoundary,
    End,
}

/// python-multipart's `MultipartParser._internal_write` over the whole body.
fn parse_multipart(boundary: &[u8], charset: &str, data: &[u8]) -> Result<FormData, FormError> {
    parse_multipart_parts(boundary, charset, data, false).map(|(form, _)| form)
}

/// [`parse_multipart`], optionally keeping the file parts' bytes.
fn parse_multipart_parts(
    boundary: &[u8],
    charset: &str,
    data: &[u8],
    keep_files: bool,
) -> Result<(FormData, Vec<UploadPart>), FormError> {
    let boundary: Vec<u8> = [b"\r\n--".as_slice(), boundary].concat();
    let bl = boundary.len();
    let len = data.len();
    let mut sink = Sink {
        charset,
        items: Vec::new(),
        keep_files,
        uploads: Vec::new(),
        part: Part::default(),
        header_name: Vec::new(),
        header_value: Vec::new(),
        fields: 0,
        files: 0,
    };
    let mut state = Mp::Start;
    let (mut index, mut part_flag, mut last_flag) = (0usize, false, false);
    let (mut header_count, mut header_size) = (0usize, 0usize);
    let (mut field_mark, mut value_mark, mut data_mark): (
        Option<usize>,
        Option<usize>,
        Option<usize>,
    ) = (None, None, None);
    let advance = |size: &mut usize| {
        *size += 1;
        if *size > MAX_HEADER_SIZE {
            Err(FormError::Malformed)
        } else {
            Ok(())
        }
    };
    let mut i = 0;
    while i < len {
        let mut c = data[i];
        match state {
            Mp::Start => {
                if c == CR || c == LF {
                    match data[i..].iter().position(|&b| b == HYPHEN) {
                        Some(p) => {
                            i += p;
                            continue;
                        }
                        None => break,
                    }
                }
                index = 0;
                state = Mp::StartBoundary;
                continue;
            }
            Mp::StartBoundary => {
                if index == bl - 2 {
                    if c == HYPHEN {
                        state = Mp::EndBoundary;
                    } else if c != CR {
                        return Err(FormError::Malformed);
                    }
                    index += 1;
                } else if index == bl - 1 {
                    if c != LF {
                        return Err(FormError::Malformed);
                    }
                    index = 0;
                    sink.part = Part::default();
                    header_count = 0;
                    header_size = 0;
                    state = Mp::HeaderFieldStart;
                } else {
                    if c != boundary[index + 2] {
                        return Err(FormError::Malformed);
                    }
                    index += 1;
                }
            }
            Mp::HeaderFieldStart => {
                index = 0;
                if c != CR {
                    header_count += 1;
                    if header_count > MAX_HEADER_COUNT {
                        return Err(FormError::Malformed);
                    }
                    header_size = 0;
                }
                field_mark = Some(i);
                state = Mp::HeaderField;
                continue;
            }
            Mp::HeaderField => {
                if c == CR && index == 0 {
                    field_mark = None;
                    state = Mp::HeadersAlmostDone;
                    i += 1;
                    continue;
                }
                index += 1;
                if c == b':' {
                    advance(&mut header_size)?;
                    if index == 1 {
                        return Err(FormError::Malformed);
                    }
                    if let Some(m) = field_mark.take() {
                        sink.header_name.extend_from_slice(&data[m..i]);
                    }
                    state = Mp::HeaderValueStart;
                } else if !is_token(c) {
                    return Err(FormError::Malformed);
                } else {
                    advance(&mut header_size)?;
                }
            }
            Mp::HeaderValueStart => {
                if c == b' ' {
                    advance(&mut header_size)?;
                    i += 1;
                    continue;
                }
                value_mark = Some(i);
                state = Mp::HeaderValue;
                continue;
            }
            Mp::HeaderValue => {
                if c == CR {
                    if let Some(m) = value_mark.take() {
                        sink.header_value.extend_from_slice(&data[m..i]);
                    }
                    sink.header_end();
                    header_size = 0;
                    state = Mp::HeaderValueAlmostDone;
                } else {
                    advance(&mut header_size)?;
                }
            }
            Mp::HeaderValueAlmostDone => {
                if c != LF {
                    return Err(FormError::Malformed);
                }
                state = Mp::HeaderFieldStart;
            }
            Mp::HeadersAlmostDone => {
                if c != LF {
                    return Err(FormError::Malformed);
                }
                sink.headers_finished()?;
                state = Mp::PartDataStart;
            }
            Mp::PartDataStart => {
                data_mark = Some(i);
                state = Mp::PartData;
                continue;
            }
            Mp::PartData => {
                let prev_index = index;
                if index == 0 {
                    match data[i..].windows(bl).position(|w| w == boundary.as_slice()) {
                        Some(p) => {
                            index = bl - 1;
                            i += p + bl - 1;
                        }
                        None => {
                            i = i.max(len.saturating_sub(bl));
                            while i < len - 1 && data[i] != boundary[0] {
                                i += 1;
                            }
                        }
                    }
                    c = data[i];
                }
                if index < bl {
                    if boundary[index] == c {
                        index += 1;
                    } else {
                        index = 0;
                    }
                } else if index == bl {
                    index += 1;
                    if c == CR {
                        part_flag = true;
                    } else if c == HYPHEN {
                        last_flag = true;
                    } else {
                        index = 0;
                    }
                } else if index == bl + 1 {
                    if part_flag {
                        part_flag = false;
                        if c == LF {
                            let end = i - index;
                            let start = data_mark.take().unwrap_or(end).min(end);
                            sink.part_data(&data[start..end])?;
                            sink.part_end(&data[start..end]);
                            sink.part = Part::default();
                            header_count = 0;
                            header_size = 0;
                            index = 0;
                            state = Mp::HeaderFieldStart;
                            i += 1;
                            continue;
                        }
                        index = 0;
                    } else if last_flag {
                        if c == HYPHEN {
                            let end = i - index;
                            let start = data_mark.take().unwrap_or(end).min(end);
                            sink.part_data(&data[start..end])?;
                            sink.part_end(&data[start..end]);
                            state = Mp::End;
                        } else {
                            index = 0;
                        }
                    }
                }
                if index == 0 && prev_index > 0 {
                    continue;
                }
            }
            Mp::EndBoundary => {
                if index == bl - 1 {
                    if c != HYPHEN {
                        return Err(FormError::Malformed);
                    }
                    index += 1;
                    state = Mp::End;
                }
            }
            Mp::End => break,
        }
        i += 1;
    }
    // A part still open at the end of the body is never added, but its data
    // has been handed to Starlette, which applies the size limit.
    if let Some(m) = data_mark {
        let end = len.saturating_sub(index);
        if end > m {
            sink.part_data(&data[m..end])?;
        }
    }
    Ok((FormData(sink.items), sink.uploads))
}

/// [`read_form`], plus the file parts' content (`UploadFile.read()`).
pub fn read_form_files(
    content_type: Option<&str>,
    body: &[u8],
) -> Result<(FormData, Vec<UploadPart>), FormError> {
    let (ctype, options) =
        parse_options_header(content_type.unwrap_or_default()).ok_or(FormError::Malformed)?;
    if ctype != "multipart/form-data" {
        return read_form(content_type, body).map(|form| (form, Vec::new()));
    }
    let charset = option(&options, "charset").unwrap_or("utf-8").to_string();
    let boundary = option(&options, "boundary")
        .ok_or_else(|| FormError::Rejected("Missing boundary in multipart.".into()))?;
    parse_multipart_parts(&latin1_bytes(boundary), &charset, body, true)
}

/// `await request.form()` for a body with this Content-Type.
pub fn read_form(content_type: Option<&str>, body: &[u8]) -> Result<FormData, FormError> {
    let (ctype, _) =
        parse_options_header(content_type.unwrap_or_default()).ok_or(FormError::Malformed)?;
    match ctype.as_str() {
        "multipart/form-data" => {
            let (_, options) = parse_options_header(content_type.unwrap_or_default())
                .ok_or(FormError::Malformed)?;
            let charset = option(&options, "charset").unwrap_or("utf-8").to_string();
            let boundary = option(&options, "boundary")
                .ok_or_else(|| FormError::Rejected("Missing boundary in multipart.".into()))?;
            parse_multipart(&latin1_bytes(boundary), &charset, body)
        }
        "application/x-www-form-urlencoded" => Ok(FormData(
            parse_urlencoded(body)
                .into_iter()
                .map(|(k, v)| (k, FormValue::Text(v)))
                .collect(),
        )),
        _ => Ok(FormData::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn vectors() -> Value {
        serde_json::from_str(include_str!("form_vectors.json")).unwrap()
    }

    #[test]
    fn options_match_python_multipart() {
        for case in vectors()["options"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let (value, options) = parse_options_header(input).unwrap();
            assert_eq!(value, case["value"].as_str().unwrap(), "{input:?}");
            let options: Vec<Value> = options.into_iter().map(|(k, v)| json!([k, v])).collect();
            assert_eq!(Value::Array(options), case["options"], "{input:?}");
        }
    }

    #[test]
    fn forms_match_starlette() {
        for case in vectors()["forms"].as_array().unwrap() {
            let ct = case["content_type"].as_str();
            let body = latin1_bytes(case["body"].as_str().unwrap());
            let got = match read_form(ct, &body) {
                Ok(form) => {
                    let items: Vec<Value> = form
                        .0
                        .into_iter()
                        .map(|(k, v)| match v {
                            FormValue::Text(t) => json!([k, t]),
                            FormValue::File { filename } => json!([k, {"filename": filename}]),
                        })
                        .collect();
                    json!({"items": items})
                }
                Err(FormError::Rejected(m)) => json!({"error": m}),
                Err(FormError::Malformed) => {
                    json!({"error": "There was an error parsing the body"})
                }
            };
            let expected = match case.get("items") {
                Some(items) => json!({"items": items}),
                None => json!({"error": case["error"]}),
            };
            assert_eq!(got, expected, "{ct:?} {:?}", case["body"]);
        }
    }

    #[test]
    fn starlette_limits() {
        let ct = "multipart/form-data; boundary=b";
        let big = "x".repeat(MAX_PART_SIZE + 1);
        let body =
            format!("--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n{big}\r\n--b--\r\n");
        assert_eq!(
            read_form(Some(ct), body.as_bytes()),
            Err(FormError::Rejected(
                "Part exceeded maximum size of 1024KB.".into()
            ))
        );
        // Never closed: still handed over, still too big.
        let open = format!("--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n{big}");
        assert!(matches!(
            read_form(Some(ct), open.as_bytes()),
            Err(FormError::Rejected(_))
        ));
        // A file part has no size limit.
        let file = format!(
            "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n\r\n{big}\r\n--b--\r\n"
        );
        assert_eq!(read_form(Some(ct), file.as_bytes()).unwrap().0.len(), 1);
        let many: String = (0..=MAX_FIELDS)
            .map(|n| format!("--b\r\nContent-Disposition: form-data; name=\"f{n}\"\r\n\r\nv\r\n"))
            .collect::<String>()
            + "--b--\r\n";
        assert_eq!(
            read_form(Some(ct), many.as_bytes()),
            Err(FormError::Rejected(
                "Too many fields. Maximum number of fields is 1000.".into()
            ))
        );
    }

    #[test]
    fn last_value_wins() {
        let form = read_form(Some("application/x-www-form-urlencoded"), b"a=1&a=2").unwrap();
        assert_eq!(form.get("a"), Some(&FormValue::Text("2".into())));
        assert_eq!(form.get("b"), None);
    }

    #[test]
    fn file_parts_keep_their_bytes() {
        let body = b"--b\r\nContent-Disposition: form-data; name=\"t\"\r\n\r\nv\r\n\
--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"r.xml\"\r\n\
Content-Type: application/xml\r\nContent-Type: text/plain\r\n\r\n<a>\xff</a>\r\n--b--\r\n";
        let (form, uploads) =
            read_form_files(Some("multipart/form-data; boundary=b"), body).unwrap();
        assert_eq!(form.0.len(), 2);
        assert_eq!(
            uploads,
            vec![UploadPart {
                field: "file".into(),
                filename: "r.xml".into(),
                content_type: Some("application/xml".into()),
                data: b"<a>\xff</a>".to_vec(),
            }]
        );
        let (_, none) = read_form_files(Some("application/x-www-form-urlencoded"), b"a=1").unwrap();
        assert!(none.is_empty());
    }
}
