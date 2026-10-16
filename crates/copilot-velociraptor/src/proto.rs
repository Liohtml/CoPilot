//! The messages of Velociraptor's `proto.API/Query` (pyvelociraptor's
//! `api.proto`), encoded as the Python protobuf runtime encodes them.
//!
//! Only `Query` is used. Its request is `VQLCollectorArgs`; each streamed
//! answer is a `VQLResponse`. The encoder writes the fields in field-number
//! order and leaves out proto3 defaults (empty strings, zeros), which is what
//! `SerializeToString()` produces, so the bytes on the wire are the Python
//! backend's byte for byte. The decoder reads every field the schema has and
//! skips unknown ones, as protobuf does.
//!
//! ```text
//! message VQLRequest       { string VQL = 1; string Name = 2; }
//! message VQLEnv           { string key = 1; string value = 2; }
//! message VQLCollectorArgs { repeated VQLRequest Query = 2; repeated VQLEnv env = 3;
//!                            uint64 max_row = 4; uint64 max_wait = 6;
//!                            float ops_per_second = 24; uint64 timeout = 25;
//!                            string org_id = 35; }
//! message VQLTypeMap       { string column = 1; string type = 2; }
//! message VQLResponse      { string Response = 1; repeated string Columns = 2;
//!                            VQLRequest Query = 3; uint64 timestamp = 4;
//!                            uint64 query_id = 5; uint64 part = 6;
//!                            uint64 total_rows = 7; repeated VQLTypeMap types = 8;
//!                            string log = 9; }
//! ```

/// `VQLRequest`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VqlRequest {
    /// `Name` (field 2).
    pub name: String,
    /// `VQL` (field 1).
    pub vql: String,
}

/// `VQLEnv`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VqlEnv {
    /// `key`.
    pub key: String,
    /// `value`.
    pub value: String,
}

/// `VQLCollectorArgs`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VqlCollectorArgs {
    /// `env` (field 3).
    pub env: Vec<VqlEnv>,
    /// `Query` (field 2).
    pub query: Vec<VqlRequest>,
    /// `max_row` (field 4).
    pub max_row: u64,
    /// `max_wait` (field 6).
    pub max_wait: u64,
    /// `ops_per_second` (field 24).
    pub ops_per_second: f32,
    /// `timeout` (field 25).
    pub timeout: u64,
    /// `org_id` (field 35).
    pub org_id: String,
}

/// `VQLTypeMap`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VqlTypeMap {
    /// `column`.
    pub column: String,
    /// `type`.
    pub ty: String,
}

/// `VQLResponse`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VqlResponse {
    /// `Response` (field 1): a JSON array of rows.
    pub response: String,
    /// `Columns` (field 2).
    pub columns: Vec<String>,
    /// `Query` (field 3).
    pub query: Option<VqlRequest>,
    /// `timestamp` (field 4).
    pub timestamp: u64,
    /// `query_id` (field 5).
    pub query_id: u64,
    /// `part` (field 6).
    pub part: u64,
    /// `total_rows` (field 7).
    pub total_rows: u64,
    /// `types` (field 8).
    pub types: Vec<VqlTypeMap>,
    /// `log` (field 9).
    pub log: String,
}

/// A message that is not valid protobuf for its schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError;

// --- wire format ------------------------------------------------------------

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn put_key(out: &mut Vec<u8>, field: u32, wire: u8) {
    put_varint(out, (u64::from(field) << 3) | u64::from(wire));
}

fn put_str(out: &mut Vec<u8>, field: u32, s: &str) {
    if s.is_empty() {
        return;
    }
    put_bytes(out, field, s.as_bytes());
}

fn put_bytes(out: &mut Vec<u8>, field: u32, b: &[u8]) {
    put_key(out, field, 2);
    put_varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn put_u64(out: &mut Vec<u8>, field: u32, v: u64) {
    if v == 0 {
        return;
    }
    put_key(out, field, 0);
    put_varint(out, v);
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn varint(&mut self) -> Result<u64, DecodeError> {
        let mut v: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = *self.buf.get(self.pos).ok_or(DecodeError)?;
            self.pos += 1;
            v |= u64::from(b & 0x7f) << shift;
            if b < 0x80 {
                return Ok(v);
            }
        }
        Err(DecodeError)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError)?;
        let s = self.buf.get(self.pos..end).ok_or(DecodeError)?;
        self.pos = end;
        Ok(s)
    }

    fn len_delimited(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = usize::try_from(self.varint()?).map_err(|_| DecodeError)?;
        self.take(n)
    }

    fn string(&mut self) -> Result<String, DecodeError> {
        String::from_utf8(self.len_delimited()?.to_vec()).map_err(|_| DecodeError)
    }

    /// The next `(field, wire type)`.
    fn key(&mut self) -> Result<(u32, u8), DecodeError> {
        let k = self.varint()?;
        let field = u32::try_from(k >> 3).map_err(|_| DecodeError)?;
        if field == 0 {
            return Err(DecodeError);
        }
        Ok((field, (k & 7) as u8))
    }

    fn skip(&mut self, wire: u8) -> Result<(), DecodeError> {
        match wire {
            0 => self.varint().map(|_| ()),
            1 => self.take(8).map(|_| ()),
            2 => self.len_delimited().map(|_| ()),
            5 => self.take(4).map(|_| ()),
            _ => Err(DecodeError),
        }
    }
}

// --- messages -----------------------------------------------------------------

impl VqlRequest {
    fn encode_into(&self, out: &mut Vec<u8>) {
        put_str(out, 1, &self.vql);
        put_str(out, 2, &self.name);
    }

    fn encoded(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(buf);
        let mut m = Self::default();
        while !r.done() {
            match r.key()? {
                (1, 2) => m.vql = r.string()?,
                (2, 2) => m.name = r.string()?,
                (_, w) => r.skip(w)?,
            }
        }
        Ok(m)
    }
}

impl VqlEnv {
    fn encoded(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_str(&mut out, 1, &self.key);
        put_str(&mut out, 2, &self.value);
        out
    }

    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(buf);
        let mut m = Self::default();
        while !r.done() {
            match r.key()? {
                (1, 2) => m.key = r.string()?,
                (2, 2) => m.value = r.string()?,
                (_, w) => r.skip(w)?,
            }
        }
        Ok(m)
    }
}

impl VqlCollectorArgs {
    /// `SerializeToString()`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for q in &self.query {
            put_bytes(&mut out, 2, &q.encoded());
        }
        for e in &self.env {
            put_bytes(&mut out, 3, &e.encoded());
        }
        put_u64(&mut out, 4, self.max_row);
        put_u64(&mut out, 6, self.max_wait);
        if self.ops_per_second != 0.0 {
            put_key(&mut out, 24, 5);
            out.extend_from_slice(&self.ops_per_second.to_le_bytes());
        }
        put_u64(&mut out, 25, self.timeout);
        put_str(&mut out, 35, &self.org_id);
        out
    }

    /// `FromString()` (the stand-in reads what clients send).
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(buf);
        let mut m = Self::default();
        while !r.done() {
            match r.key()? {
                (2, 2) => m.query.push(VqlRequest::decode(r.len_delimited()?)?),
                (3, 2) => m.env.push(VqlEnv::decode(r.len_delimited()?)?),
                (4, 0) => m.max_row = r.varint()?,
                (6, 0) => m.max_wait = r.varint()?,
                (24, 5) => {
                    let b = r.take(4)?;
                    m.ops_per_second = f32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                }
                (25, 0) => m.timeout = r.varint()?,
                (35, 2) => m.org_id = r.string()?,
                (_, w) => r.skip(w)?,
            }
        }
        Ok(m)
    }
}

impl VqlTypeMap {
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(buf);
        let mut m = Self::default();
        while !r.done() {
            match r.key()? {
                (1, 2) => m.column = r.string()?,
                (2, 2) => m.ty = r.string()?,
                (_, w) => r.skip(w)?,
            }
        }
        Ok(m)
    }
}

impl VqlResponse {
    /// `FromString()`.
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(buf);
        let mut m = Self::default();
        while !r.done() {
            match r.key()? {
                (1, 2) => m.response = r.string()?,
                (2, 2) => m.columns.push(r.string()?),
                (3, 2) => m.query = Some(VqlRequest::decode(r.len_delimited()?)?),
                (4, 0) => m.timestamp = r.varint()?,
                (5, 0) => m.query_id = r.varint()?,
                (6, 0) => m.part = r.varint()?,
                (7, 0) => m.total_rows = r.varint()?,
                (8, 2) => m.types.push(VqlTypeMap::decode(r.len_delimited()?)?),
                (9, 2) => m.log = r.string()?,
                (_, w) => r.skip(w)?,
            }
        }
        Ok(m)
    }

    /// `SerializeToString()` (the stand-in answers with it).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_str(&mut out, 1, &self.response);
        for c in &self.columns {
            put_bytes(&mut out, 2, c.as_bytes());
        }
        if let Some(q) = &self.query {
            put_bytes(&mut out, 3, &q.encoded());
        }
        put_u64(&mut out, 4, self.timestamp);
        put_u64(&mut out, 5, self.query_id);
        put_u64(&mut out, 6, self.part);
        put_u64(&mut out, 7, self.total_rows);
        for t in &self.types {
            let mut b = Vec::new();
            put_str(&mut b, 1, &t.column);
            put_str(&mut b, 2, &t.ty);
            put_bytes(&mut out, 8, &b);
        }
        put_str(&mut out, 9, &self.log);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Recorded with `api_pb2.VQLCollectorArgs(...).SerializeToString().hex()`
    /// (protobuf 6.33).
    #[test]
    fn requests_encode_as_python_does() {
        let args = VqlCollectorArgs {
            max_wait: 1,
            org_id: "root".into(),
            query: vec![VqlRequest {
                name: "VQLRequest".into(),
                vql: "SELECT 1".into(),
            }],
            ..Default::default()
        };
        assert_eq!(
            hex(&args.encode()),
            "12160a0853454c4543542031120a56514c5265717565737430019a0204726f6f74"
        );
        let verify = VqlCollectorArgs {
            max_wait: 60,
            query: vec![VqlRequest {
                name: "ClientQuery".into(),
                vql: "SELECT * FROM info()".into(),
            }],
            ..Default::default()
        };
        assert_eq!(
            hex(&verify.encode()),
            "12230a1453454c454354202a2046524f4d20696e666f2829120b436c69656e745175657279303c"
        );
        let empty = VqlCollectorArgs {
            max_wait: 1,
            query: vec![VqlRequest {
                name: "VQLRequest".into(),
                vql: String::new(),
            }],
            ..Default::default()
        };
        assert_eq!(hex(&empty.encode()), "120c120a56514c526571756573743001");
        assert_eq!(VqlCollectorArgs::decode(&args.encode()), Ok(args));
    }

    #[test]
    fn responses_round_trip_and_skip_unknown_fields() {
        let r = VqlResponse {
            response: "[]".into(),
            log: "x".into(),
            columns: vec!["a".into()],
            ..Default::default()
        };
        assert_eq!(hex(&r.encode()), "0a025b5d1201614a0178");
        let mut bytes = r.encode();
        // field 50, varint 7; field 51, fixed64.
        bytes.extend_from_slice(&[0x90, 0x03, 0x07, 0x99, 0x03, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(VqlResponse::decode(&bytes), Ok(r));
        assert_eq!(VqlResponse::decode(&[0x0a, 0x05, b'a']), Err(DecodeError));
        assert_eq!(VqlResponse::decode(&[0x0a, 0x01, 0xff]), Err(DecodeError));
    }
}
