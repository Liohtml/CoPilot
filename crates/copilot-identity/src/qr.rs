//! The enrolment QR code as a `data:image/png;base64,…` URI —
//! `qrcode.make(otpauth_url, box_size=6, border=2)` saved as PNG.
//!
//! Same geometry and error correction (M) as the Python image; the PNG is a
//! 1-bit greyscale image written here directly (no image stack). The bytes
//! differ from Pillow's — only the decoded content matters.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use qrcode::{Color, EcLevel, QrCode};

/// Pixels per module.
const BOX: usize = 6;
/// Quiet zone, in modules.
const BORDER: usize = 2;

/// The text could not be encoded (longer than a version-40 code holds).
#[derive(Debug, thiserror::Error)]
#[error("QR encoding failed: {0}")]
pub struct QrError(String);

fn chunk(png: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    png.extend_from_slice(&len.to_be_bytes());
    let start = png.len();
    png.extend_from_slice(kind);
    png.extend_from_slice(data);
    let crc = crc32fast::hash(&png[start..]);
    png.extend_from_slice(&crc.to_be_bytes());
}

/// The PNG bytes of `text`'s QR code.
pub fn qr_png(text: &str) -> Result<Vec<u8>, QrError> {
    let code = QrCode::with_error_correction_level(text, EcLevel::M)
        .map_err(|e| QrError(e.to_string()))?;
    let modules = code.width();
    let colors = code.to_colors();
    let size = (modules + 2 * BORDER) * BOX;
    let module = |px: usize| (px / BOX).checked_sub(BORDER).filter(|&m| m < modules);
    let mut raw = Vec::with_capacity(size * (size.div_ceil(8) + 1));
    for y in 0..size {
        raw.push(0); // filter: none
        let (mut byte, mut bits) = (0u8, 0u32);
        for x in 0..size {
            let dark = match (module(x), module(y)) {
                (Some(mx), Some(my)) => colors[my * modules + mx] == Color::Dark,
                _ => false,
            };
            byte = (byte << 1) | u8::from(!dark);
            bits += 1;
            if bits == 8 {
                raw.push(byte);
                (byte, bits) = (0, 0);
            }
        }
        if bits > 0 {
            raw.push(byte << (8 - bits));
        }
    }
    let side = u32::try_from(size).map_err(|e| QrError(e.to_string()))?;
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&side.to_be_bytes());
    ihdr.extend_from_slice(&side.to_be_bytes());
    ihdr.extend_from_slice(&[1, 0, 0, 0, 0]); // 1-bit greyscale, deflate, no interlace
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(&mut png, b"IHDR", &ihdr);
    chunk(
        &mut png,
        b"IDAT",
        &miniz_oxide::deflate::compress_to_vec_zlib(&raw, 6),
    );
    chunk(&mut png, b"IEND", &[]);
    Ok(png)
}

/// `_generate_qr_data_uri`.
pub fn qr_data_uri(text: &str) -> Result<String, QrError> {
    Ok(format!(
        "data:image/png;base64,{}",
        STANDARD.encode(qr_png(text)?)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read our own PNG back: chunk CRCs, IHDR, the inflated rows.
    fn decode_png(png: &[u8]) -> (usize, Vec<Vec<bool>>) {
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        let (mut i, mut side, mut idat) = (8, 0usize, Vec::new());
        while i < png.len() {
            let len = u32::from_be_bytes(png[i..i + 4].try_into().unwrap()) as usize;
            let kind = &png[i + 4..i + 8];
            let data = &png[i + 8..i + 8 + len];
            let crc = u32::from_be_bytes(png[i + 8 + len..i + 12 + len].try_into().unwrap());
            assert_eq!(crc, crc32fast::hash(&png[i + 4..i + 8 + len]));
            match kind {
                b"IHDR" => {
                    side = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
                    assert_eq!(&data[8..], &[1, 0, 0, 0, 0]);
                }
                b"IDAT" => idat.extend_from_slice(data),
                _ => {}
            }
            i += 12 + len;
        }
        let raw = miniz_oxide::inflate::decompress_to_vec_zlib(&idat).unwrap();
        let stride = side.div_ceil(8) + 1;
        let rows = raw
            .chunks(stride)
            .map(|row| {
                assert_eq!(row[0], 0);
                (0..side)
                    .map(|x| row[1 + x / 8] & (0x80 >> (x % 8)) != 0)
                    .collect()
            })
            .collect();
        (side, rows)
    }

    #[test]
    fn decodes_to_the_otpauth_uri() {
        let uri = "otpauth://totp/CoPilot:alice%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=CoPilot";
        let png = qr_png(uri).unwrap();
        let (side, rows) = decode_png(&png);
        let code = QrCode::with_error_correction_level(uri, EcLevel::M).unwrap();
        assert_eq!(side, (code.width() + 4) * 6);
        // White quiet zone.
        assert!(rows[0].iter().all(|&white| white));
        let mut img = rqrr::PreparedImage::prepare_from_greyscale(side, side, |x, y| {
            if rows[y][x] { 255 } else { 0 }
        });
        let grids = img.detect_grids();
        assert_eq!(grids.len(), 1);
        let (meta, content) = grids[0].decode().unwrap();
        assert_eq!(content, uri);
        assert_eq!(meta.ecc_level, 0); // M
        let data_uri = qr_data_uri(uri).unwrap();
        assert!(data_uri.starts_with("data:image/png;base64,iVBORw0KGgo"));
    }
}
