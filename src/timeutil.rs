//! 上海时区日期/时间工具。自动同步的两个随机槽位、批次日期都以 Asia/Shanghai 为准，
//! 不依赖机器本地时区。

use chrono::{DateTime, FixedOffset, NaiveDate, TimeZone, Utc};

pub const SHANGHAI: FixedOffset = match FixedOffset::east_opt(8 * 3600) {
    Some(o) => o,
    None => FixedOffset::east_opt(0).unwrap(),
};

/// 当前上海日期（YYYY-MM-DD）
pub fn shanghai_today() -> NaiveDate {
    Utc::now().with_timezone(&SHANGHAI).date_naive()
}

/// 指定时刻的上海日期
pub fn shanghai_date_at(now: DateTime<Utc>) -> NaiveDate {
    now.with_timezone(&SHANGHAI).date_naive()
}

/// 指定时刻的上海分钟数（0-1439）
pub fn shanghai_minute_at(now: DateTime<Utc>) -> i32 {
    let dt = now.with_timezone(&SHANGHAI);
    dt.format("%H").to_string().parse::<i32>().unwrap_or(0) * 60
        + dt.format("%M").to_string().parse::<i32>().unwrap_or(0)
}

/// 上海日期 + 当天分钟数 → UTC 时刻
pub fn shanghai_minute_to_utc(date: NaiveDate, minute_of_day: i32) -> DateTime<Utc> {
    let hour = minute_of_day / 60;
    let minute = minute_of_day % 60;
    let naive = date
        .and_hms_opt(hour as u32, minute as u32, 0)
        .unwrap_or_else(|| date.and_hms_opt(0, 0, 0).unwrap());
    SHANGHAI
        .from_local_datetime(&naive)
        .single()
        .unwrap_or_else(|| SHANGHAI.from_utc_datetime(&naive))
        .with_timezone(&Utc)
}

/// 上海今天 00:00 对应的 UTC 时刻
pub fn shanghai_day_start_utc() -> DateTime<Utc> {
    shanghai_minute_to_utc(shanghai_today(), 0)
}

/// 格式化为上海时间 `2026-11-14 15:04`
pub fn format_shanghai(dt: &DateTime<Utc>) -> String {
    dt.with_timezone(&SHANGHAI)
        .format("%Y-%m-%d %H:%M")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shanghai_offset_is_plus_eight() {
        // 2026-11-14 00:00 UTC = 08:00 上海
        let utc = Utc.with_ymd_and_hms(2026, 11, 14, 0, 0, 0).unwrap();
        assert_eq!(shanghai_date_at(utc).to_string(), "2026-11-14");
        assert_eq!(shanghai_minute_at(utc), 8 * 60);
    }

    #[test]
    fn minute_round_trips() {
        let date = NaiveDate::from_ymd_opt(2026, 11, 14).unwrap();
        let utc = shanghai_minute_to_utc(date, 9 * 60 + 30);
        assert_eq!(shanghai_date_at(utc).to_string(), "2026-11-14");
        assert_eq!(shanghai_minute_at(utc), 9 * 60 + 30);
    }
}
