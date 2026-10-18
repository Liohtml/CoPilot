//! `mimetypes.guess_type(filename)[0]` as CPython 3.11 answers it on this
//! host: the built-in table, then every `mime.types` file of
//! `mimetypes.knownfiles` that exists (later files win, as `init()` reads
//! them), the `suffix_map` / `encodings_map` rewrites, the `data:` URL rule
//! and `urlparse`'s scheme split. httpx's multipart encoder guesses a file
//! part's `Content-Type` with it (`application/octet-stream` when it finds
//! none), which is what the CAPE submission sends.
//!
//! The host's files are read once per process, as Python's `init()` does at
//! the first guess. `mimetypes_vectors` in `file_analysis_vectors.json` pins
//! the table and the guesses.

use std::collections::HashMap;
use std::sync::LazyLock;

/// `mimetypes.knownfiles` (Linux).
pub const KNOWN_FILES: &[&str] = &[
    "/etc/mime.types",
    "/etc/httpd/mime.types",
    "/etc/httpd/conf/mime.types",
    "/etc/apache/mime.types",
    "/etc/apache2/mime.types",
    "/usr/local/etc/httpd/conf/mime.types",
    "/usr/local/lib/netscape/mime.types",
    "/usr/local/etc/httpd/conf/mime.types",
    "/usr/local/etc/mime.types",
];

const SUFFIX_MAP: &[(&str, &str)] = &[
    (".svgz", ".svg.gz"),
    (".tgz", ".tar.gz"),
    (".taz", ".tar.gz"),
    (".tz", ".tar.gz"),
    (".tbz2", ".tar.bz2"),
    (".txz", ".tar.xz"),
];

const ENCODINGS: &[&str] = &[".gz", ".Z", ".bz2", ".xz", ".br"];

/// `urllib.parse.uses_params`.
const USES_PARAMS: &[&str] = &[
    "", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp", "rtsp", "rtspu", "sip", "sips",
    "mms", "sftp", "tel",
];

/// Python 3.11's `_types_map_default` (strict), in its order.
pub const DEFAULT_TYPES: &[(&str, &str)] = &[
    (".js", "application/javascript"),
    (".mjs", "application/javascript"),
    (".json", "application/json"),
    (".webmanifest", "application/manifest+json"),
    (".doc", "application/msword"),
    (".dot", "application/msword"),
    (".wiz", "application/msword"),
    (".nq", "application/n-quads"),
    (".nt", "application/n-triples"),
    (".bin", "application/octet-stream"),
    (".a", "application/octet-stream"),
    (".dll", "application/octet-stream"),
    (".exe", "application/octet-stream"),
    (".o", "application/octet-stream"),
    (".obj", "application/octet-stream"),
    (".so", "application/octet-stream"),
    (".oda", "application/oda"),
    (".pdf", "application/pdf"),
    (".p7c", "application/pkcs7-mime"),
    (".ps", "application/postscript"),
    (".ai", "application/postscript"),
    (".eps", "application/postscript"),
    (".trig", "application/trig"),
    (".m3u", "application/vnd.apple.mpegurl"),
    (".m3u8", "application/vnd.apple.mpegurl"),
    (".xls", "application/vnd.ms-excel"),
    (".xlb", "application/vnd.ms-excel"),
    (".ppt", "application/vnd.ms-powerpoint"),
    (".pot", "application/vnd.ms-powerpoint"),
    (".ppa", "application/vnd.ms-powerpoint"),
    (".pps", "application/vnd.ms-powerpoint"),
    (".pwz", "application/vnd.ms-powerpoint"),
    (".wasm", "application/wasm"),
    (".bcpio", "application/x-bcpio"),
    (".cpio", "application/x-cpio"),
    (".csh", "application/x-csh"),
    (".dvi", "application/x-dvi"),
    (".gtar", "application/x-gtar"),
    (".hdf", "application/x-hdf"),
    (".h5", "application/x-hdf5"),
    (".latex", "application/x-latex"),
    (".mif", "application/x-mif"),
    (".cdf", "application/x-netcdf"),
    (".nc", "application/x-netcdf"),
    (".p12", "application/x-pkcs12"),
    (".pfx", "application/x-pkcs12"),
    (".ram", "application/x-pn-realaudio"),
    (".pyc", "application/x-python-code"),
    (".pyo", "application/x-python-code"),
    (".sh", "application/x-sh"),
    (".shar", "application/x-shar"),
    (".swf", "application/x-shockwave-flash"),
    (".sv4cpio", "application/x-sv4cpio"),
    (".sv4crc", "application/x-sv4crc"),
    (".tar", "application/x-tar"),
    (".tcl", "application/x-tcl"),
    (".tex", "application/x-tex"),
    (".texi", "application/x-texinfo"),
    (".texinfo", "application/x-texinfo"),
    (".roff", "application/x-troff"),
    (".t", "application/x-troff"),
    (".tr", "application/x-troff"),
    (".man", "application/x-troff-man"),
    (".me", "application/x-troff-me"),
    (".ms", "application/x-troff-ms"),
    (".ustar", "application/x-ustar"),
    (".src", "application/x-wais-source"),
    (".xsl", "application/xml"),
    (".rdf", "application/xml"),
    (".wsdl", "application/xml"),
    (".xpdl", "application/xml"),
    (".zip", "application/zip"),
    (".3gp", "audio/3gpp"),
    (".3gpp", "audio/3gpp"),
    (".3g2", "audio/3gpp2"),
    (".3gpp2", "audio/3gpp2"),
    (".aac", "audio/aac"),
    (".adts", "audio/aac"),
    (".loas", "audio/aac"),
    (".ass", "audio/aac"),
    (".au", "audio/basic"),
    (".snd", "audio/basic"),
    (".mp3", "audio/mpeg"),
    (".mp2", "audio/mpeg"),
    (".opus", "audio/opus"),
    (".aif", "audio/x-aiff"),
    (".aifc", "audio/x-aiff"),
    (".aiff", "audio/x-aiff"),
    (".ra", "audio/x-pn-realaudio"),
    (".wav", "audio/x-wav"),
    (".avif", "image/avif"),
    (".bmp", "image/bmp"),
    (".gif", "image/gif"),
    (".ief", "image/ief"),
    (".jpg", "image/jpeg"),
    (".jpe", "image/jpeg"),
    (".jpeg", "image/jpeg"),
    (".heic", "image/heic"),
    (".heif", "image/heif"),
    (".png", "image/png"),
    (".svg", "image/svg+xml"),
    (".tiff", "image/tiff"),
    (".tif", "image/tiff"),
    (".ico", "image/vnd.microsoft.icon"),
    (".ras", "image/x-cmu-raster"),
    (".pnm", "image/x-portable-anymap"),
    (".pbm", "image/x-portable-bitmap"),
    (".pgm", "image/x-portable-graymap"),
    (".ppm", "image/x-portable-pixmap"),
    (".rgb", "image/x-rgb"),
    (".xbm", "image/x-xbitmap"),
    (".xpm", "image/x-xpixmap"),
    (".xwd", "image/x-xwindowdump"),
    (".eml", "message/rfc822"),
    (".mht", "message/rfc822"),
    (".mhtml", "message/rfc822"),
    (".nws", "message/rfc822"),
    (".css", "text/css"),
    (".csv", "text/csv"),
    (".html", "text/html"),
    (".htm", "text/html"),
    (".n3", "text/n3"),
    (".txt", "text/plain"),
    (".bat", "text/plain"),
    (".c", "text/plain"),
    (".h", "text/plain"),
    (".ksh", "text/plain"),
    (".pl", "text/plain"),
    (".srt", "text/plain"),
    (".rtx", "text/richtext"),
    (".tsv", "text/tab-separated-values"),
    (".vtt", "text/vtt"),
    (".py", "text/x-python"),
    (".etx", "text/x-setext"),
    (".sgm", "text/x-sgml"),
    (".sgml", "text/x-sgml"),
    (".vcf", "text/x-vcard"),
    (".xml", "text/xml"),
    (".mp4", "video/mp4"),
    (".mpeg", "video/mpeg"),
    (".m1v", "video/mpeg"),
    (".mpa", "video/mpeg"),
    (".mpe", "video/mpeg"),
    (".mpg", "video/mpeg"),
    (".mov", "video/quicktime"),
    (".qt", "video/quicktime"),
    (".webm", "video/webm"),
    (".avi", "video/x-msvideo"),
    (".movie", "video/x-sgi-movie"),
];

/// The strict table after `init()`: the defaults, then the host's files.
pub(crate) fn build(files: &[String]) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = DEFAULT_TYPES
        .iter()
        .map(|(e, t)| ((*e).to_string(), (*t).to_string()))
        .collect();
    for content in files {
        for line in content.lines() {
            let mut words: Vec<&str> = line.split_whitespace().collect();
            if let Some(i) = words.iter().position(|w| w.starts_with('#')) {
                words.truncate(i);
            }
            let Some((ty, suffixes)) = words.split_first() else {
                continue;
            };
            for suffix in suffixes {
                map.insert(format!(".{suffix}"), (*ty).to_string());
            }
        }
    }
    map
}

static TABLE: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    let files: Vec<String> = KNOWN_FILES
        .iter()
        .filter(|f| std::path::Path::new(f).is_file())
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .collect();
    build(&files)
});

/// `posixpath.splitext(p)`.
pub fn splitext(p: &str) -> (&str, &str) {
    let sep = p.rfind('/');
    let Some(dot) = p.rfind('.') else {
        return (p, "");
    };
    let start = sep.map_or(0, |s| s + 1);
    if sep.is_some_and(|s| dot < s) {
        return (p, "");
    }
    if p[start..dot].chars().any(|c| c != '.') {
        (&p[..dot], &p[dot..])
    } else {
        (p, "")
    }
}

/// The scheme `urlsplit` finds, and the path `urlparse` leaves.
fn scheme_and_path(url: &str) -> Option<(String, String)> {
    let trimmed: String = url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let colon = trimmed.find(':')?;
    let candidate = &trimmed[..colon];
    let first = candidate.chars().next()?;
    if !first.is_ascii_alphabetic()
        || !candidate
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return None;
    }
    let scheme = candidate.to_ascii_lowercase();
    let mut rest = &trimmed[colon + 1..];
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        rest = &after[end..];
    }
    if let Some(i) = rest.find('#') {
        rest = &rest[..i];
    }
    if let Some(i) = rest.find('?') {
        rest = &rest[..i];
    }
    let mut path = rest.to_string();
    if USES_PARAMS.contains(&scheme.as_str()) && path.contains(';') {
        let last_slash = path.rfind('/').unwrap_or(0);
        if let Some(semi) = path[last_slash..].find(';') {
            path.truncate(last_slash + semi);
        }
    }
    Some((scheme, path))
}

/// `mimetypes.guess_type(url)[0]` against a given strict table.
pub fn guess_with(table: &HashMap<String, String>, url: &str) -> Option<String> {
    let (scheme, path) = match scheme_and_path(url) {
        Some((scheme, path)) if scheme.chars().count() > 1 => (Some(scheme), path),
        _ => (None, url.to_string()),
    };
    if scheme.as_deref() == Some("data") {
        let comma = path.find(',')?;
        let semi = path[..comma].find(';');
        let ty = &path[..semi.unwrap_or(comma)];
        return Some(if ty.contains('=') || !ty.contains('/') {
            "text/plain".into()
        } else {
            ty.to_string()
        });
    }
    let (mut base, mut ext) = {
        let (b, e) = splitext(&path);
        (b.to_string(), e.to_string())
    };
    while let Some((_, to)) = SUFFIX_MAP
        .iter()
        .find(|(from, _)| *from == copilot_jinja::unicode::lower(&ext))
    {
        let joined = format!("{base}{to}");
        let (b, e) = splitext(&joined);
        let (b, e) = (b.to_string(), e.to_string());
        base = b;
        ext = e;
    }
    if ENCODINGS.contains(&ext.as_str()) {
        let (_, e) = splitext(&base);
        ext = e.to_string();
    }
    table.get(&copilot_jinja::unicode::lower(&ext)).cloned()
}

/// `mimetypes.guess_type(url)[0]` on this host.
pub fn guess_type(url: &str) -> Option<String> {
    guess_with(&TABLE, url)
}

/// httpx's `_guess_content_type(filename)`.
pub fn httpx_content_type(filename: &str) -> String {
    if filename.is_empty() {
        return "application/octet-stream".into();
    }
    guess_type(filename).unwrap_or_else(|| "application/octet-stream".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitext_like_posixpath() {
        assert_eq!(splitext("a.tar.gz"), ("a.tar", ".gz"));
        assert_eq!(splitext(".bashrc"), (".bashrc", ""));
        assert_eq!(splitext("..x"), ("..x", ""));
        assert_eq!(splitext("d.d/x"), ("d.d/x", ""));
        assert_eq!(splitext("x."), ("x", "."));
        assert_eq!(splitext("a/.b.c"), ("a/.b", ".c"));
    }

    #[test]
    fn guesses_follow_the_tables() {
        let table =
            build(&["application/x-msdos-program exe # dos\n# comment\nfoo/bar baz".into()]);
        assert_eq!(
            guess_with(&table, "a.EXE").as_deref(),
            Some("application/x-msdos-program")
        );
        assert_eq!(
            guess_with(&table, "a.tgz").as_deref(),
            Some("application/x-tar")
        );
        assert_eq!(
            guess_with(&table, "a.pdf.gz").as_deref(),
            Some("application/pdf")
        );
        assert_eq!(guess_with(&table, "x.baz").as_deref(), Some("foo/bar"));
        assert_eq!(guess_with(&table, "sample"), None);
        assert_eq!(
            guess_with(&table, "data:image/png;base64,xx").as_deref(),
            Some("image/png")
        );
        assert_eq!(
            guess_with(&table, "http://h/a.pdf?x=1").as_deref(),
            Some("application/pdf")
        );
    }
}
