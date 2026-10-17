//! `zipfile.ZipFile(io.BytesIO(body)).extractall(path)` — what
//! `write_log_file` does with a Mimecast SIEM download.
//!
//! The archive is read as CPython 3.11's `zipfile` reads it: the end of
//! central directory record (`_EndRecData`: the last 22 bytes, else the last
//! 64 KiB searched backwards), the central directory (the `concat` offset of
//! an archive with data in front, names decoded as UTF-8 under flag bit 11,
//! else cp437, cut at a NUL), then per member in directory order the local
//! header (its signature, the name it repeats), stored or deflated data and
//! its CRC-32. Each member is extracted as `_extract_member` does: `/`
//! separated, empty, `.` and `..` parts dropped, the upper directories
//! created, a name ending in `/` a directory — so a failure part-way leaves
//! the members before it on disk, as Python does.
//!
//! What `write_log_file` makes of any failure is one answer (`Unable to
//! extract zip file.`), so the error here is only logged. Not read: Zip64
//! archives, bzip2 and LZMA members and encrypted ones (Python extracts the
//! first three; Mimecast's downloads are deflated archives, RUST_MIGRATION.md
//! §4).

use std::io::Read as _;
use std::path::{Path, PathBuf};

/// Why an archive could not be extracted (logged only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipError(pub String);

impl std::fmt::Display for ZipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn bad(text: impl Into<String>) -> ZipError {
    ZipError(text.into())
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

const END_SIG: &[u8; 4] = b"PK\x05\x06";
const END_SIZE: usize = 22;
const CENTRAL_SIG: &[u8; 4] = b"PK\x01\x02";
const CENTRAL_SIZE: usize = 46;
const LOCAL_SIG: &[u8; 4] = b"PK\x03\x04";
const LOCAL_SIZE: usize = 30;
const ZIP64_LOCATOR_SIG: &[u8; 4] = b"PK\x06\x07";

/// One central-directory entry.
#[derive(Debug, Clone)]
struct Member {
    name: String,
    raw_name: Vec<u8>,
    flags: u16,
    method: u16,
    crc: u32,
    compressed: usize,
    header_offset: usize,
}

/// `_EndRecData`: the record and where it starts.
fn end_record(data: &[u8]) -> Result<(usize, &[u8]), ZipError> {
    let not_zip = || bad("File is not a zip file");
    if data.len() < END_SIZE {
        return Err(not_zip());
    }
    let tail = &data[data.len() - END_SIZE..];
    if &tail[..4] == END_SIG && tail[20..] == [0, 0] {
        return Ok((data.len() - END_SIZE, tail));
    }
    let from = data.len().saturating_sub((1 << 16) + END_SIZE);
    let window = &data[from..];
    let start = window
        .windows(4)
        .rposition(|w| w == END_SIG)
        .ok_or_else(not_zip)?;
    let record = window.get(start..start + END_SIZE).ok_or_else(not_zip)?;
    Ok((from + start, record))
}

/// CPython's cp437 codec for the bytes above 0x7F.
const CP437_HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";

fn cp437(bytes: &[u8]) -> String {
    let high: Vec<char> = CP437_HIGH.chars().collect();
    bytes
        .iter()
        .map(|&b| {
            if b < 0x80 {
                char::from(b)
            } else {
                high[usize::from(b - 0x80)]
            }
        })
        .collect()
}

fn decode_name(raw: &[u8], flags: u16) -> Result<String, ZipError> {
    if flags & 0x800 != 0 {
        String::from_utf8(raw.to_vec()).map_err(|e| bad(format!("bad UTF-8 name: {e}")))
    } else {
        Ok(cp437(raw))
    }
}

/// `_RealGetContents`: the members in directory order.
fn members(data: &[u8]) -> Result<Vec<Member>, ZipError> {
    let (location, record) = end_record(data)?;
    if location >= 20 && &data[location - 20..location - 16] == ZIP64_LOCATOR_SIG {
        return Err(bad("Zip64 archives are not read"));
    }
    let size_cd = u32_at(record, 12) as usize;
    let offset_cd = u32_at(record, 16) as usize;
    let concat = location as i64 - size_cd as i64 - offset_cd as i64;
    let start_dir = offset_cd as i64 + concat;
    if start_dir < 0 {
        return Err(bad("Bad offset for central directory"));
    }
    let start_dir = start_dir as usize;
    let directory = data
        .get(start_dir..)
        .map(|d| &d[..size_cd.min(d.len())])
        .unwrap_or_default();
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < size_cd {
        let entry = directory
            .get(at..at + CENTRAL_SIZE)
            .ok_or_else(|| bad("Truncated central directory"))?;
        if &entry[..4] != CENTRAL_SIG {
            return Err(bad("Bad magic number for central directory"));
        }
        let extract_version = entry[6];
        if extract_version > 63 {
            return Err(bad(format!(
                "zip file version {:.1}",
                f64::from(extract_version) / 10.0
            )));
        }
        let flags = u16_at(entry, 8);
        let method = u16_at(entry, 10);
        let crc = u32_at(entry, 16);
        let compressed = u32_at(entry, 20) as usize;
        let name_len = u16_at(entry, 28) as usize;
        let extra_len = u16_at(entry, 30) as usize;
        let comment_len = u16_at(entry, 32) as usize;
        let header_offset = u32_at(entry, 42) as i64 + concat;
        let raw_name = directory
            .get(at + CENTRAL_SIZE..at + CENTRAL_SIZE + name_len)
            .unwrap_or_default()
            .to_vec();
        let mut name = decode_name(&raw_name, flags)?;
        // `ZipInfo.__init__`: the name ends at a NUL.
        if let Some(nul) = name.find('\0') {
            name.truncate(nul);
        }
        out.push(Member {
            name,
            raw_name,
            flags,
            method,
            crc,
            compressed,
            header_offset: usize::try_from(header_offset).map_err(|_| bad("Bad offset"))?,
        });
        at += CENTRAL_SIZE + name_len + extra_len + comment_len;
    }
    Ok(out)
}

/// `ZipFile.open(member)`: the local header checked; the member's raw
/// data. Its failures come before the target file is opened.
fn open_member<'a>(data: &'a [u8], m: &Member) -> Result<&'a [u8], ZipError> {
    let header = data
        .get(m.header_offset..m.header_offset + LOCAL_SIZE)
        .ok_or_else(|| bad("Truncated file header"))?;
    if &header[..4] != LOCAL_SIG {
        return Err(bad("Bad magic number for file header"));
    }
    let name_len = u16_at(header, 26) as usize;
    let extra_len = u16_at(header, 28) as usize;
    let name_at = m.header_offset + LOCAL_SIZE;
    let local_name = data
        .get(name_at..name_at + name_len)
        .ok_or_else(|| bad("Truncated file header"))?;
    if m.flags & 0x20 != 0 {
        return Err(bad("compressed patched data (flag bit 5)"));
    }
    if m.flags & 0x40 != 0 {
        return Err(bad("strong encryption (flag bit 6)"));
    }
    let local_flags = u16_at(header, 6);
    let local = decode_name(local_name, local_flags)?;
    let directory_name = decode_name(&m.raw_name, m.flags)?;
    if local != directory_name {
        return Err(bad(format!(
            "File name in directory {directory_name:?} and header {local:?} differ."
        )));
    }
    if m.flags & 0x1 != 0 {
        return Err(bad(format!(
            "File {:?} is encrypted, password required for extraction",
            m.name
        )));
    }
    if !matches!(m.method, 0 | 8) {
        return Err(bad("That compression method is not supported"));
    }
    let start = name_at + name_len + extra_len;
    // A short read is found while copying, as Python's `ZipExtFile` finds it.
    Ok(data
        .get(start..)
        .map_or(&[][..], |rest| &rest[..m.compressed.min(rest.len())]))
}

/// `shutil.copyfileobj(source, target)` reads 64 KiB at a time, and the
/// read that reaches the end checks the CRC: what was written before it
/// stays when that fails.
const COPY_BUFSIZE: usize = 64 * 1024;

/// The member's content (decompressed, CRC checked), or what Python's copy
/// wrote before the read that failed, and the failure.
fn read_member(raw: &[u8], m: &Member) -> (Vec<u8>, Option<ZipError>) {
    let content = match m.method {
        0 => raw.to_vec(),
        _ => {
            let mut out = Vec::new();
            if let Err(e) = flate2::read::DeflateDecoder::new(raw).read_to_end(&mut out) {
                return (
                    Vec::new(),
                    Some(bad(format!("Error -3 while decompressing data: {e}"))),
                );
            }
            out
        }
    };
    if raw.len() < m.compressed {
        return (Vec::new(), Some(bad("Truncated file data")));
    }
    if crc32fast::hash(&content) != m.crc {
        let kept = content.len().saturating_sub(1) / COPY_BUFSIZE * COPY_BUFSIZE;
        return (
            content[..kept].to_vec(),
            Some(bad(format!("Bad CRC-32 for file {:?}", m.name))),
        );
    }
    (content, None)
}

/// `_extract_member`'s target under `root`.
fn target_of(root: &Path, name: &str) -> PathBuf {
    let mut target = root.to_path_buf();
    for part in name.split('/') {
        if !part.is_empty() && part != "." && part != ".." {
            target.push(part);
        }
    }
    target
}

/// `ZipFile(io.BytesIO(data)).extractall(root)`.
pub fn extract_all(data: &[u8], root: &Path) -> Result<(), ZipError> {
    let members = members(data)?;
    for m in &members {
        // `extractall` extracts `namelist()`, each name through `getinfo`: a
        // name the directory holds twice is its last entry, both times.
        let m = members
            .iter()
            .rev()
            .find(|other| other.name == m.name)
            .unwrap_or(m);
        let target = target_of(root, &m.name);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| bad(e.to_string()))?;
        }
        if m.name.ends_with('/') {
            if !target.is_dir() {
                std::fs::create_dir(&target).map_err(|e| bad(e.to_string()))?;
            }
            continue;
        }
        let raw = open_member(data, m)?;
        let (content, failure) = read_member(raw, m);
        std::fs::write(&target, content).map_err(|e| bad(e.to_string()))?;
        if let Some(failure) = failure {
            return Err(failure);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// A minimal archive of `(name, data, deflate)` members.
    pub(crate) fn archive(members: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data, deflate) in members {
            let offset = out.len() as u32;
            let body = if *deflate {
                let mut e =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(data).expect("deflate");
                e.finish().expect("deflate")
            } else {
                data.to_vec()
            };
            let crc = crc32fast::hash(data);
            let method: u16 = if *deflate { 8 } else { 0 };
            let mut local = Vec::new();
            local.extend_from_slice(LOCAL_SIG);
            local.extend_from_slice(&20u16.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&method.to_le_bytes());
            local.extend_from_slice(&[0; 4]);
            local.extend_from_slice(&crc.to_le_bytes());
            local.extend_from_slice(&(body.len() as u32).to_le_bytes());
            local.extend_from_slice(&(data.len() as u32).to_le_bytes());
            local.extend_from_slice(&(name.len() as u16).to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&local);
            out.extend_from_slice(&body);
            central.extend_from_slice(CENTRAL_SIG);
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0; 4]);
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(body.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0; 12]);
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(END_SIG);
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("copilot-zip-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn extracts_stored_and_deflated_members_with_python_s_paths() {
        let data = archive(&[
            ("a.log", b"x=1|y=2\n", true),
            ("../../b.log", b"plain", false),
            ("dir/", b"", false),
            ("dir/c.log", b"c", true),
        ]);
        let root = scratch("ok");
        extract_all(&data, &root).expect("extract");
        assert_eq!(std::fs::read(root.join("a.log")).expect("a"), b"x=1|y=2\n");
        assert_eq!(std::fs::read(root.join("b.log")).expect("b"), b"plain");
        assert_eq!(std::fs::read(root.join("dir/c.log")).expect("c"), b"c");
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn refuses_what_zipfile_refuses() {
        let root = scratch("bad");
        assert_eq!(
            extract_all(b"not a zip at all, but long enough", &root),
            Err(bad("File is not a zip file"))
        );
        let mut data = archive(&[("a.log", b"hello", false)]);
        // Corrupt the stored data: the CRC no longer matches.
        data[30 + 5] = b'j';
        assert_eq!(
            extract_all(&data, &root),
            Err(bad("Bad CRC-32 for file \"a.log\""))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cp437_names_decode_as_python_does() {
        assert_eq!(cp437(b"caf\x82"), "café");
        assert_eq!(cp437(&[0xff]), "\u{a0}");
        assert_eq!(CP437_HIGH.chars().count(), 128);
    }
}
