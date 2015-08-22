use chrono::{DateTime, UTC, TimeZone};

use super::{Tag, DerResult, FromTlv};
use super::DerErrorKind::{InvalidTag, InvalidVal};

#[derive(Debug)]
pub struct Time {
    pub time: DateTime<UTC>,
}

impl FromTlv for Time {
    fn from_tlv(tag: Tag, value: &[u8]) -> DerResult<Time> {
        let val = match tag {
            Tag::UtcTime => Time::from_utc_time(value),
            Tag::GeneralizedTime => Time::from_gen_time(value),
            _ => return der_err!(InvalidTag, "unexpected tag: {:?}", tag),
        };
        match val {
            Some(val) => Ok(val),
            None => return der_err!(InvalidVal, "invalid Time value"),
        }
    }
}

impl Time {
    // value: YYMMDDhhmmss
    fn from_date(y: &[u8], r: &[u8]) -> Option<Time> {
        macro_rules! s(
            ($v:ident, $i:expr) => ({
                let val0 = $v[$i];
                let val1 = $v[$i + 1];
                if val0 < b'0' || val0 > b'9' || val1 < b'0' || val1 > b'9' {
                    return None;
                }
                ((val0 - b'0') * 10 + (val1 - b'0')) as u32
            })
        );

        let year = s!(y, 0) as i32;
        let year = if y.len() == 4 {
            year * 100 + (s!(y, 2) as i32)
        } else {
            if year >= 50 {
                year + 1000
            } else {
                year + 2000
            }
        };

        let month = s!(r, 0);
        let day = s!(r, 2);
        let hour = s!(r, 4);
        let min = s!(r, 6);
        let sec = s!(r, 8);

        // hhmmss == '240000' is not permitted
        if hour == 24 {
            return None;
        }

        let time = UTC.ymd_opt(year, month, day).single()
                .and_then(|s| { s.and_hms_opt(hour, min, sec) });

        match time {
            Some(time) => Some(Time { time: time }),
            None => None,
        }
    }

    fn from_gen_time(value: &[u8]) -> Option<Time> {
        let len = value.len();
        if len != 15 {
            return None;
        }

        if value[14] != b'Z' {
            return None;
        }

        Time::from_date(&value[..4], &value[4..14])
    }

    fn from_utc_time(value: &[u8]) -> Option<Time> {
        let len = value.len();
        if len != 13 {
            return None;
        }

        if value[12] != b'Z' {
            return None;
        }

        Time::from_date(&value[..2], &value[2..12])
    }
}
