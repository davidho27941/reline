//! RFC 3339 formatting without a date-time dependency. Every output carries an explicit offset.

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SS+00:00`.
pub fn format_rfc3339_utc(secs: i64) -> String {
    let (y, m, d, hh, mm, ss) = civil_from_unix(secs);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}+00:00")
}

/// Format Unix milliseconds at a fixed offset, e.g. `+09:00`, for user-facing displays.
pub fn format_rfc3339_offset(millis: i64, offset_minutes: i32) -> String {
    let secs = millis.div_euclid(1000) + i64::from(offset_minutes) * 60;
    let (y, m, d, hh, mm, ss) = civil_from_unix(secs);
    let sign = if offset_minutes < 0 { '-' } else { '+' };
    let off = offset_minutes.unsigned_abs();
    format!(
        "{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}{sign}{:02}:{:02}",
        off / 60,
        off % 60
    )
}

fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    (
        y,
        m,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    )
}

// Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proven_case_timestamps() {
        // Report 7.1: max timestamp 1790947350257 ms is 2026-10-02 22:22:30 at UTC+9.
        assert_eq!(
            format_rfc3339_offset(1_790_947_350_257, 9 * 60),
            "2026-10-02T22:22:30+09:00"
        );
        // Report 12.2: Status.plist Date 2026-10-03 04:06:37 +0000.
        assert_eq!(
            format_rfc3339_utc(1_791_000_397),
            "2026-10-03T04:06:37+00:00"
        );
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00+00:00");
    }
}
