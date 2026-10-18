//! Python's `zipfile` as python-docx uses it: members read by name (the
//! last of a duplicated name wins, as `NameToInfo` keeps it), stored or
//! deflated, their CRC checked; written with `ZIP_DEFLATED`, a member per
//! `writestr(name, data)` (local time, `0o600 << 16`, made on Unix).
//!
//! Compressed bytes come from flate2 at zlib's default level, not CPython's
//! zlib: the members and their contents are Python's, the archive's bytes
//! are not (a §4 row).

use std::io::{Read, Write};

/// A read or write failure (`BadZipFile` and friends: a bare 500).
#[derive(Debug, Clone, PartialEq)]
pub struct ZipError(pub String);

impl std::fmt::Display for ZipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ZipError {}

/// One member of the central directory.
#[derive(Debug, Clone)]
pub struct Member {
    /// The member's name.
    pub name: String,
    method: u16,
    flags: u16,
    crc: u32,
    compressed_size: u64,
    size: u64,
    header_offset: u64,
}

/// An archive opened for reading.
#[derive(Debug, Clone)]
pub struct Archive<'a> {
    data: &'a [u8],
    /// The members in central-directory order.
    pub members: Vec<Member>,
}

fn u16_at(d: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(i)?, *d.get(i + 1)?]))
}

fn u32_at(d: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *d.get(i)?,
        *d.get(i + 1)?,
        *d.get(i + 2)?,
        *d.get(i + 3)?,
    ]))
}

/// `zipfile._EndRecData`: the end-of-central-directory record's offset.
fn end_record(d: &[u8]) -> Option<usize> {
    const SIG: &[u8] = b"PK\x05\x06";
    if d.len() >= 22 && &d[d.len() - 22..d.len() - 18] == SIG && d[d.len() - 2..] == [0, 0] {
        return Some(d.len() - 22);
    }
    let lo = d.len().saturating_sub(65535 + 22);
    let window = &d[lo..];
    let pos = window.windows(4).rposition(|w| w == SIG)?;
    let at = lo + pos;
    if at + 22 > d.len() {
        return None;
    }
    Some(at)
}

/// `zipfile.is_zipfile`.
pub fn is_zipfile(d: &[u8]) -> bool {
    end_record(d).is_some()
}

impl<'a> Archive<'a> {
    /// `ZipFile(file)`: the central directory read.
    pub fn open(data: &'a [u8]) -> Result<Self, ZipError> {
        let bad = |m: &str| ZipError(m.to_string());
        let eocd = end_record(data).ok_or_else(|| bad("File is not a zip file"))?;
        let count = u16_at(data, eocd + 10).ok_or_else(|| bad("Truncated file header"))?;
        let cd_size = u32_at(data, eocd + 12).ok_or_else(|| bad("Truncated file header"))? as usize;
        let cd_offset =
            u32_at(data, eocd + 16).ok_or_else(|| bad("Truncated file header"))? as usize;
        if count == 0xFFFF || cd_offset == 0xFFFF_FFFF {
            return Err(bad("ZIP64 archives are not supported"));
        }
        // `concat`: bytes prepended to the archive.
        let concat = eocd
            .checked_sub(cd_size + cd_offset)
            .ok_or_else(|| bad("Bad offset for central directory"))?;
        let mut pos = cd_offset + concat;
        let mut members = Vec::new();
        while pos < eocd {
            if data.get(pos..pos + 4) != Some(b"PK\x01\x02") {
                return Err(bad("Bad magic number for central directory"));
            }
            let field =
                |o: usize| u16_at(data, pos + o).ok_or_else(|| bad("Truncated central directory"));
            let field32 =
                |o: usize| u32_at(data, pos + o).ok_or_else(|| bad("Truncated central directory"));
            let flags = field(8)?;
            let method = field(10)?;
            let crc = field32(16)?;
            let compressed_size = u64::from(field32(20)?);
            let size = u64::from(field32(24)?);
            let name_len = usize::from(field(28)?);
            let extra_len = usize::from(field(30)?);
            let comment_len = usize::from(field(32)?);
            let header_offset = u64::from(field32(42)?) + concat as u64;
            let raw = data
                .get(pos + 46..pos + 46 + name_len)
                .ok_or_else(|| bad("Truncated central directory"))?;
            let name = if flags & 0x800 != 0 {
                String::from_utf8_lossy(raw).into_owned()
            } else {
                raw.iter().map(|&b| cp437(b)).collect()
            };
            members.push(Member {
                name,
                method,
                flags,
                crc,
                compressed_size,
                size,
                header_offset,
            });
            pos += 46 + name_len + extra_len + comment_len;
        }
        Ok(Self { data, members })
    }

    /// `ZipFile.read(name)`: `None` when no member has that name (`KeyError`).
    pub fn read(&self, name: &str) -> Option<Result<Vec<u8>, ZipError>> {
        let m = self.members.iter().rev().find(|m| m.name == name)?;
        Some(self.read_member(m))
    }

    fn read_member(&self, m: &Member) -> Result<Vec<u8>, ZipError> {
        let bad = |s: String| ZipError(s);
        let h = m.header_offset as usize;
        if self.data.get(h..h + 4) != Some(b"PK\x03\x04") {
            return Err(bad("Bad magic number for file header".into()));
        }
        let name_len = usize::from(u16_at(self.data, h + 26).unwrap_or(0));
        let extra_len = usize::from(u16_at(self.data, h + 28).unwrap_or(0));
        if m.flags & 0x1 != 0 {
            return Err(bad(format!(
                "File {:?} is encrypted, password required for extraction",
                m.name
            )));
        }
        let start = h + 30 + name_len + extra_len;
        let raw = self
            .data
            .get(start..start + m.compressed_size as usize)
            .ok_or_else(|| bad("Truncated file header".into()))?;
        let out = match m.method {
            0 => raw.to_vec(),
            8 => {
                let mut v = Vec::with_capacity(m.size as usize);
                flate2::read::DeflateDecoder::new(raw)
                    .read_to_end(&mut v)
                    .map_err(|e| bad(format!("Error -3 while decompressing data: {e}")))?;
                v
            }
            other => {
                return Err(bad(format!("compression type {other}")));
            }
        };
        if crc32fast::hash(&out) != m.crc {
            return Err(bad(format!("Bad CRC-32 for file {:?}", m.name)));
        }
        Ok(out)
    }
}

fn cp437(b: u8) -> char {
    const HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";
    if b < 0x80 {
        char::from(b)
    } else {
        HIGH.chars().nth(usize::from(b - 0x80)).unwrap_or('?')
    }
}

/// `ZipFile(file, "w", compression=ZIP_DEFLATED)` and its `writestr`s.
#[derive(Debug)]
pub struct Writer {
    out: Vec<u8>,
    central: Vec<u8>,
    count: u16,
    dos_time: u16,
    dos_date: u16,
}

impl Writer {
    /// A writer whose members carry `now` (local time, as `time.localtime()`).
    pub fn new(now: chrono::NaiveDateTime) -> Self {
        use chrono::{Datelike, Timelike};
        let year = now.year().clamp(1980, 2107) as u16;
        let dos_date = ((year - 1980) << 9) | ((now.month() as u16) << 5) | now.day() as u16;
        let dos_time =
            ((now.hour() as u16) << 11) | ((now.minute() as u16) << 5) | (now.second() as u16 / 2);
        Self {
            out: Vec::new(),
            central: Vec::new(),
            count: 0,
            dos_time,
            dos_date,
        }
    }

    /// `writestr(name, data)`.
    pub fn write(&mut self, name: &str, data: &[u8]) -> Result<(), ZipError> {
        let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
        enc.write_all(data)
            .map_err(|e| ZipError(format!("Error while compressing: {e}")))?;
        let compressed = enc
            .finish()
            .map_err(|e| ZipError(format!("Error while compressing: {e}")))?;
        let crc = crc32fast::hash(data);
        let flags: u16 = if name.is_ascii() { 0 } else { 0x800 };
        let name_bytes = name.as_bytes();
        let to32 = |n: usize| u32::try_from(n).map_err(|_| ZipError("ZIP64 not supported".into()));
        let offset = to32(self.out.len())?;
        let csize = to32(compressed.len())?;
        let usize_ = to32(data.len())?;
        let name_len =
            u16::try_from(name_bytes.len()).map_err(|_| ZipError("name too long".into()))?;
        // Local file header.
        self.out.extend_from_slice(b"PK\x03\x04");
        self.out.extend_from_slice(&20u16.to_le_bytes());
        self.out.extend_from_slice(&flags.to_le_bytes());
        self.out.extend_from_slice(&8u16.to_le_bytes());
        self.out.extend_from_slice(&self.dos_time.to_le_bytes());
        self.out.extend_from_slice(&self.dos_date.to_le_bytes());
        self.out.extend_from_slice(&crc.to_le_bytes());
        self.out.extend_from_slice(&csize.to_le_bytes());
        self.out.extend_from_slice(&usize_.to_le_bytes());
        self.out.extend_from_slice(&name_len.to_le_bytes());
        self.out.extend_from_slice(&0u16.to_le_bytes());
        self.out.extend_from_slice(name_bytes);
        self.out.extend_from_slice(&compressed);
        // Its central directory entry.
        let c = &mut self.central;
        c.extend_from_slice(b"PK\x01\x02");
        c.extend_from_slice(&((3u16 << 8) | 20).to_le_bytes());
        c.extend_from_slice(&20u16.to_le_bytes());
        c.extend_from_slice(&flags.to_le_bytes());
        c.extend_from_slice(&8u16.to_le_bytes());
        c.extend_from_slice(&self.dos_time.to_le_bytes());
        c.extend_from_slice(&self.dos_date.to_le_bytes());
        c.extend_from_slice(&crc.to_le_bytes());
        c.extend_from_slice(&csize.to_le_bytes());
        c.extend_from_slice(&usize_.to_le_bytes());
        c.extend_from_slice(&name_len.to_le_bytes());
        c.extend_from_slice(&0u16.to_le_bytes()); // extra
        c.extend_from_slice(&0u16.to_le_bytes()); // comment
        c.extend_from_slice(&0u16.to_le_bytes()); // disk
        c.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        c.extend_from_slice(&(0o600u32 << 16).to_le_bytes());
        c.extend_from_slice(&offset.to_le_bytes());
        c.extend_from_slice(name_bytes);
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// `close()`: the central directory and its end record.
    pub fn finish(mut self) -> Vec<u8> {
        let cd_offset = self.out.len() as u32;
        let cd_size = self.central.len() as u32;
        self.out.extend_from_slice(&self.central);
        self.out.extend_from_slice(b"PK\x05\x06");
        self.out.extend_from_slice(&0u16.to_le_bytes());
        self.out.extend_from_slice(&0u16.to_le_bytes());
        self.out.extend_from_slice(&self.count.to_le_bytes());
        self.out.extend_from_slice(&self.count.to_le_bytes());
        self.out.extend_from_slice(&cd_size.to_le_bytes());
        self.out.extend_from_slice(&cd_offset.to_le_bytes());
        self.out.extend_from_slice(&0u16.to_le_bytes());
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let now = chrono::NaiveDate::from_ymd_opt(2026, 1, 2)
            .and_then(|d| d.and_hms_opt(3, 4, 6))
            .unwrap();
        let mut w = Writer::new(now);
        w.write("a.xml", b"<a/>").unwrap();
        w.write("b/c.bin", &[0u8; 1000]).unwrap();
        let bytes = w.finish();
        assert!(is_zipfile(&bytes));
        let a = Archive::open(&bytes).unwrap();
        assert_eq!(a.members.len(), 2);
        assert_eq!(a.read("a.xml").unwrap().unwrap(), b"<a/>");
        assert_eq!(a.read("b/c.bin").unwrap().unwrap(), vec![0u8; 1000]);
        assert!(a.read("nope").is_none());
    }
}
