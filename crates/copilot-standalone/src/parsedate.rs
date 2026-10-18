//! `email.utils.parsedate` (CPython 3.11's `_parseaddr._parsedate_tz`),
//! the date reader `StaticFiles.is_not_modified` compares
//! `If-Modified-Since` with: the date's fields as a tuple — `(year, month,
//! day, hour, minute, second)`, the time zone dropped — or `None`.

const MONTHS: [&str; 24] = [
    "jan",
    "feb",
    "mar",
    "apr",
    "may",
    "jun",
    "jul",
    "aug",
    "sep",
    "oct",
    "nov",
    "dec",
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
];
const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/// Python's `str.split()` whitespace.
fn is_py_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

/// `int(text)` (ASCII digits; the sign, the surrounding whitespace and the
/// single underscores between digits Python accepts).
fn py_int(text: &str) -> Option<i64> {
    let t = text.trim_matches(is_py_space);
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return None;
    }
    let mut n: i64 = 0;
    for c in digits.chars() {
        if c == '_' {
            continue;
        }
        let d = c.to_digit(10)?;
        n = n.checked_mul(10)?.checked_add(i64::from(d))?;
    }
    Some(if neg { -n } else { n })
}

/// The fields `parsedate` returns that a comparison looks at.
pub type DateTuple = (i64, i64, i64, i64, i64, i64);

/// `email.utils.parsedate(data)[:6]`.
pub fn parsedate(data: &str) -> Option<DateTuple> {
    let mut data: Vec<String> = data
        .split(is_py_space)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if data.is_empty() {
        return None;
    }
    if data[0].ends_with(',') || DAYS.contains(&data[0].to_lowercase().as_str()) {
        data.remove(0);
    } else if let Some(i) = data[0].rfind(',') {
        data[0] = data[0][i + 1..].to_string();
    }
    if data.len() == 3 {
        let stuff: Vec<String> = data[0].split('-').map(String::from).collect();
        if stuff.len() == 3 {
            let rest = data[1..].to_vec();
            data = stuff;
            data.extend(rest);
        }
    }
    if data.len() == 4 {
        let s = data[3].clone();
        let i = s.find('+').or_else(|| s.find('-'));
        match i {
            Some(i) if i > 0 => {
                data.truncate(3);
                data.push(s[..i].to_string());
                data.push(s[i..].to_string());
            }
            _ => data.push(String::new()),
        }
    }
    if data.len() < 5 {
        return None;
    }
    data.truncate(5);
    let (mut dd, mut mm, mut yy, mut tm, mut tz) = (
        data[0].clone(),
        data[1].clone(),
        data[2].clone(),
        data[3].clone(),
        data[4].clone(),
    );
    if dd.is_empty() || mm.is_empty() || yy.is_empty() {
        return None;
    }
    mm = mm.to_lowercase();
    if !MONTHS.contains(&mm.as_str()) {
        let swapped = dd.to_lowercase();
        dd = mm;
        mm = swapped;
        if !MONTHS.contains(&mm.as_str()) {
            return None;
        }
    }
    let mut month = i64::try_from(MONTHS.iter().position(|m| *m == mm)?).ok()? + 1;
    if month > 12 {
        month -= 12;
    }
    if dd.ends_with(',') {
        dd.pop();
    }
    if yy.find(':').is_some_and(|i| i > 0) {
        std::mem::swap(&mut yy, &mut tm);
    }
    if yy.ends_with(',') {
        yy.pop();
        if yy.is_empty() {
            return None;
        }
    }
    if !yy.chars().next().is_some_and(char::is_numeric) {
        std::mem::swap(&mut yy, &mut tz);
    }
    let _ = &tz;
    if tm.ends_with(',') {
        tm.pop();
    }
    let parts: Vec<String> = tm.split(':').map(String::from).collect();
    let (thh, tmm, tss) = match parts.len() {
        2 => (parts[0].clone(), parts[1].clone(), "0".to_string()),
        3 => (parts[0].clone(), parts[1].clone(), parts[2].clone()),
        1 if parts[0].contains('.') => {
            let dotted: Vec<String> = parts[0].split('.').map(String::from).collect();
            match dotted.len() {
                2 => (dotted[0].clone(), dotted[1].clone(), "0".to_string()),
                3 => (dotted[0].clone(), dotted[1].clone(), dotted[2].clone()),
                _ => return None,
            }
        }
        _ => return None,
    };
    let mut year = py_int(&yy)?;
    let day = py_int(&dd)?;
    let hour = py_int(&thh)?;
    let minute = py_int(&tmm)?;
    let second = py_int(&tss)?;
    if year < 100 {
        if year > 68 {
            year += 1900;
        } else {
            year += 2000;
        }
    }
    Some((year, month, day, hour, minute, second))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_three_http_formats() {
        let want = Some((1994, 11, 15, 8, 12, 31));
        assert_eq!(parsedate("Tue, 15 Nov 1994 08:12:31 GMT"), want);
        assert_eq!(parsedate("Tuesday, 15-Nov-94 08:12:31 GMT"), want);
        assert_eq!(parsedate("Tue Nov 15 08:12:31 1994"), want);
        assert_eq!(parsedate("garbage"), None);
        assert_eq!(parsedate(""), None);
    }
}
