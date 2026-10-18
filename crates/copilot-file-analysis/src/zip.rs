//! The part of `zipfile.ZipFile` the screenshot fetch uses: `namelist()`
//! (the central directory's names, in its order) and `read(name)` (the last
//! entry of that name, stored or deflated, its CRC-32 checked). Anything
//! `zipfile` would refuse — no end record, a truncated entry, an encrypted
//! or otherwise compressed member, a bad CRC — is an error, which the caller
//! turns into "no screenshots" exactly as Python's `except Exception` does.

use std::io::Read as _;

/// A refused archive (the caller only needs to know it failed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadZip(pub &'static str);

struct Entry {
    name: String,
    flags: u16,
    method: u16,
    crc: u32,
    compressed: usize,
    size: usize,
    offset: usize,
}

/// An opened archive.
pub struct Archive<'a> {
    data: &'a [u8],
    entries: Vec<Entry>,
}

fn u16_at(d: &[u8], at: usize) -> Result<u16, BadZip> {
    d.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or(BadZip("truncated"))
}

fn u32_at(d: &[u8], at: usize) -> Result<u32, BadZip> {
    d.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or(BadZip("truncated"))
}

/// CP437 as `zipfile` decodes a name without the UTF-8 flag.
fn cp437(bytes: &[u8]) -> String {
    const HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";
    let high: Vec<char> = HIGH.chars().collect();
    bytes
        .iter()
        .map(|&b| {
            if b < 0x80 {
                char::from(b)
            } else {
                high.get(usize::from(b - 0x80)).copied().unwrap_or('?')
            }
        })
        .collect()
}

impl<'a> Archive<'a> {
    /// `zipfile.ZipFile(io.BytesIO(data))`.
    pub fn open(data: &'a [u8]) -> Result<Self, BadZip> {
        if data.len() < 22 {
            return Err(BadZip("File is not a zip file"));
        }
        let lowest = data.len().saturating_sub(22 + 65_535);
        let mut eocd = None;
        let mut at = data.len() - 22;
        loop {
            if u32_at(data, at)? == 0x0605_4b50 {
                eocd = Some(at);
                break;
            }
            if at == lowest {
                break;
            }
            at -= 1;
        }
        let eocd = eocd.ok_or(BadZip("File is not a zip file"))?;
        let count = usize::from(u16_at(data, eocd + 10)?);
        let cd_size = u32_at(data, eocd + 12)? as usize;
        let cd_offset = u32_at(data, eocd + 16)? as usize;
        if cd_offset == 0xFFFF_FFFF || count == 0xFFFF {
            return Err(BadZip("zip64 archives are not read here"));
        }
        // `concat`: bytes prepended to the archive shift every offset.
        let concat = eocd
            .checked_sub(cd_size + cd_offset)
            .ok_or(BadZip("Bad offset for central directory"))?;
        let mut pos = cd_offset + concat;
        let end = pos + cd_size;
        let mut entries = Vec::new();
        while pos < end {
            if u32_at(data, pos)? != 0x0201_4b50 {
                return Err(BadZip("Bad magic number for central directory"));
            }
            let flags = u16_at(data, pos + 8)?;
            let method = u16_at(data, pos + 10)?;
            let crc = u32_at(data, pos + 16)?;
            let compressed = u32_at(data, pos + 20)? as usize;
            let size = u32_at(data, pos + 24)? as usize;
            let name_len = usize::from(u16_at(data, pos + 28)?);
            let extra_len = usize::from(u16_at(data, pos + 30)?);
            let comment_len = usize::from(u16_at(data, pos + 32)?);
            let offset = u32_at(data, pos + 42)? as usize + concat;
            let raw = data
                .get(pos + 46..pos + 46 + name_len)
                .ok_or(BadZip("truncated"))?;
            let name = if flags & 0x800 != 0 {
                String::from_utf8_lossy(raw).into_owned()
            } else {
                cp437(raw)
            };
            entries.push(Entry {
                name,
                flags,
                method,
                crc,
                compressed,
                size,
                offset,
            });
            pos += 46 + name_len + extra_len + comment_len;
        }
        Ok(Self { data, entries })
    }

    /// `namelist()`.
    pub fn names(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.name.clone()).collect()
    }

    /// `read(name)`.
    pub fn read(&self, name: &str) -> Result<Vec<u8>, BadZip> {
        let e = self
            .entries
            .iter()
            .rev()
            .find(|e| e.name == name)
            .ok_or(BadZip("There is no item named in the archive"))?;
        if e.flags & 0x1 != 0 {
            return Err(BadZip("encrypted, password required"));
        }
        if u32_at(self.data, e.offset)? != 0x0403_4b50 {
            return Err(BadZip("Bad magic number for file header"));
        }
        let name_len = usize::from(u16_at(self.data, e.offset + 26)?);
        let extra_len = usize::from(u16_at(self.data, e.offset + 28)?);
        let start = e.offset + 30 + name_len + extra_len;
        let raw = self
            .data
            .get(start..start + e.compressed)
            .ok_or(BadZip("truncated"))?;
        let out = match e.method {
            0 => raw.to_vec(),
            8 => {
                let mut out = Vec::with_capacity(e.size);
                flate2::read::DeflateDecoder::new(raw)
                    .read_to_end(&mut out)
                    .map_err(|_| BadZip("Error -3 while decompressing data"))?;
                out
            }
            _ => return Err(BadZip("That compression method is not supported")),
        };
        if out.len() != e.size || crc32fast::hash(&out) != e.crc {
            return Err(BadZip("Bad CRC-32"));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `zipfile` output: `b.png` deflated, `a.jpg` stored, `c.txt`.
    fn sample() -> Vec<u8> {
        use std::io::Write as _;
        let mut files: Vec<(&str, Vec<u8>, u16)> = vec![
            ("b.png", b"PNGDATA PNGDATA PNGDATA".to_vec(), 8),
            ("a.jpg", b"JPEG".to_vec(), 0),
            ("c.txt", b"text".to_vec(), 0),
        ];
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data, method) in &mut files {
            let stored = if *method == 8 {
                let mut enc =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                enc.write_all(data).unwrap();
                enc.finish().unwrap()
            } else {
                data.clone()
            };
            let crc = crc32fast::hash(data);
            let offset = out.len() as u32;
            out.extend(0x0403_4b50u32.to_le_bytes());
            out.extend([20, 0, 0, 0]);
            out.extend(method.to_le_bytes());
            out.extend([0; 4]);
            out.extend(crc.to_le_bytes());
            out.extend((stored.len() as u32).to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((name.len() as u16).to_le_bytes());
            out.extend([0, 0]);
            out.extend(name.as_bytes());
            out.extend(&stored);
            central.extend(0x0201_4b50u32.to_le_bytes());
            central.extend([20, 0, 20, 0, 0, 0]);
            central.extend(method.to_le_bytes());
            central.extend([0; 4]);
            central.extend(crc.to_le_bytes());
            central.extend((stored.len() as u32).to_le_bytes());
            central.extend((data.len() as u32).to_le_bytes());
            central.extend((name.len() as u16).to_le_bytes());
            central.extend([0; 12]);
            central.extend(offset.to_le_bytes());
            central.extend(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        out.extend(&central);
        out.extend(0x0605_4b50u32.to_le_bytes());
        out.extend([0; 4]);
        out.extend(3u16.to_le_bytes());
        out.extend(3u16.to_le_bytes());
        out.extend((central.len() as u32).to_le_bytes());
        out.extend(cd_offset.to_le_bytes());
        out.extend([0, 0]);
        out
    }

    #[test]
    fn reads_what_zipfile_reads() {
        let data = sample();
        let z = Archive::open(&data).unwrap();
        assert_eq!(z.names(), ["b.png", "a.jpg", "c.txt"]);
        assert_eq!(z.read("b.png").unwrap(), b"PNGDATA PNGDATA PNGDATA");
        assert_eq!(z.read("a.jpg").unwrap(), b"JPEG");
        assert!(Archive::open(b"not a zip at all, sorry!").is_err());
        let mut bad = data.clone();
        let at = bad.windows(4).position(|w| w == b"JPEG").unwrap();
        bad[at] = b'X';
        assert_eq!(
            Archive::open(&bad).unwrap().read("a.jpg"),
            Err(BadZip("Bad CRC-32"))
        );
    }
}
