use std::cmp::min;

#[cfg(feature="coverage_loop_bucketing_afl")]
#[inline(always)]
fn loop_bucketing_afl(count: usize) -> usize {
    match count {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        _ => 128,
    }
}

#[cfg(feature="coverage_loop_bucketing_symcts")]
#[inline(always)]
fn loop_bucketing_symcts(count: usize) -> usize {
    if count <= 16 {
        count
    }
    else {
        let v = min((count-16).next_power_of_two(), 0x1000);
        // get the highest bit set
        16 + v
    }
}

#[inline(always)]
fn loop_bucketing_triggered_only(count: usize) -> usize {
    if count == 0 { 0 } else { 1 }
}

#[cfg(feature="coverage_loop_bucketing_afl")]
#[inline(always)]
fn get_bucketed_hitcount(count: usize) -> usize {
    loop_bucketing_afl(count)
}
#[cfg(feature="coverage_loop_bucketing_symcts")]
#[inline(always)]
fn get_bucketed_hitcount(count: usize) -> usize {
    loop_bucketing_symcts(count)
}
#[cfg(not(any(feature="coverage_loop_bucketing_afl", feature="coverage_loop_bucketing_symcts")))]
#[inline(always)]
fn get_bucketed_hitcount(_count: usize) -> usize {
    loop_bucketing_triggered_only(count)
}

#[cfg(feature="coverage_hitcounts_outer")]
#[inline(always)]
pub fn get_bucketed_hitcount_outer(count: usize) -> usize {
    get_bucketed_hitcount(count)
}
#[cfg(not(feature="coverage_hitcounts_outer"))]
#[inline(always)]
pub fn get_bucketed_hitcount_outer(count: usize) -> usize {
    loop_bucketing_triggered_only(count)
}

#[cfg(feature="coverage_hitcounts_inner")]
#[inline(always)]
pub fn get_bucketed_hitcount_inner(count: usize) -> usize {
    get_bucketed_hitcount(count)
}

#[cfg(not(feature="coverage_hitcounts_inner"))]
#[inline(always)]
pub fn get_bucketed_hitcount_inner(count: usize) -> usize {
    loop_bucketing_triggered_only(count)
}