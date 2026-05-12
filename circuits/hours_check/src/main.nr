// audit-core: Business hours policy check
// Proves: action occurred between allowed_start_hour and allowed_end_hour UTC
// Private input keeps exact timestamp off-chain
// Public hour bounds let the auditor see what window was enforced

fn main(
    timestamp: u64,              // private: unix seconds UTC
    allowed_start_hour: pub u8,  // public: 6
    allowed_end_hour: pub u8,    // public: 22
) -> pub bool {
    let seconds_in_day: u64 = 86400;
    let seconds_in_hour: u64 = 3600;
    let seconds_today = timestamp % seconds_in_day;
    let hour = (seconds_today / seconds_in_hour) as u8;
    let result = (hour >= allowed_start_hour) & (hour < allowed_end_hour);
    assert(result);
    result
}
