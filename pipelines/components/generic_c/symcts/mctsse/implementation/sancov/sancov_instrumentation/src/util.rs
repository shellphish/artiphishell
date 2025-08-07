use cty::c_void;
use sancov_shared::util::align_down;

pub fn find_elf_start(p: *const c_void) -> *const c_void {
    let pagesize = page_size::get();

    let expected = b"\x7fELF";
    let mut cur = align_down(p as usize, pagesize);
    loop {
        let cur_comp = cur as *const [u8; 4];
        if unsafe { &*cur_comp } == expected {
            return cur_comp as *const c_void;
        }
        cur = cur.checked_sub(pagesize).unwrap();
    }
}

// #[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
// pub struct ProcSelfMapsRegion {
//     pub start: *const c_void,
//     pub end: *const c_void,
//     pub name: String,
// }

// pub fn parse_proc_self_maps() -> Vec<ProcSelfMapsRegion> {
//     let mut regions = Vec::new();
//     let mut f = File::open("/proc/self/maps").expect("failed to open /proc/self/maps");
//     let mut buf = String::new();
//     f.read_to_string(&mut buf).expect("failed to read /proc/self/maps");
//     let mut cur_region: Option<(*const c_void, *const c_void, String)> = None;
//     for line in buf.lines() {
//         let mut parts = line.split_whitespace();
//         let start = parts.next().unwrap().parse::<usize>().unwrap() as *const c_void;
//         let end = parts.next().unwrap().parse::<usize>().unwrap() as *const c_void;
//         let name = parts.next().unwrap().to_string();
//         match cur_region {
//             Some((cur_start, cur_end, cur_name)) => {
//                 if start == cur_end && cur_name == name {
//                     cur_region = Some((cur_start, end, cur_name));
//                 } else {
//                     regions.push((cur_start, cur_end, cur_name));
//                     cur_region = Some((start, end, name));
//                 }
//             }
//             None => {
//                 cur_region = Some((start, end, name));
//             }
//         }
//     }
//     if cur_region.is_some() {
//         regions.push(cur_region.unwrap());
//     }
//     regions
//         .into_iter()
//         .map(|(start, end, name)| ProcSelfMapsRegion { start, end, name })
//         .collect()
// }
