
// use std::error::Error;
// use clap::{Arg, App, SubCommand};

// fn main() -> Result<(), &'static dyn Error>{
//     let matches = App::new("distributed_solver")
//         .version("0.1")
//         .author("Lukas Dresel")
//         .about("Distributed solver backend")
//         .arg(Arg::with_name("server_type")
//                 .required(true)
//                 .takes_value(true)
//                 .possible_values(&["tcp", "udp", "unix"])
//             )
//         .get_matches();
//     println!("{:?}", matches);
//     Ok(())
// }
use std::sync::{RwLock,Arc};
use std::{thread,time};
use distributed_solver::constraint_graph::{AstGraph};

fn parallel_test () {
    let locked_graph: Arc<RwLock<AstGraph>> = Arc::new(RwLock::new(Default::default()));

    let lg1 = Arc::clone(&locked_graph);
    let handle1 = std::thread::spawn(move || {
        for _ in 0..10 {
            println!("Reader thread 1: {:?}", lg1.read());
            thread::sleep(time::Duration::from_secs(1));
        }
    });

    let lg2 = Arc::clone(&locked_graph);
    let handle2 = std::thread::spawn(move || {
        for _ in 0..10 {
            println!("Reader thread 2: {:?}", lg2.read());
            thread::sleep(time::Duration::from_secs(1));
        }
    });
    let n1 = locked_graph.write().unwrap().ast_var(String::from("var1"), 64);
    let mut last_node = n1;
    for i in 0..10 {
        let mut g = locked_graph.write().unwrap();
        let offset = g.ast_const_int(1337+i, 64);
        last_node = g.ast_add(last_node, offset);
        println!("Added new add node: Adding {:x}, got {:?}", i+1337,last_node);
        thread::sleep(time::Duration::from_millis(200 * i as u64));
    }
    handle1.join().unwrap();
    handle2.join().unwrap();
}
fn main() {
    parallel_test();
    // let mut g = AstGraph::new();
    // let n1 = g.ast_var(String::from("var1"), 64);
    // let n2 = g.ast_const_int(0x1337, 64);
    // let n3 = g.ast_add(n1, n2);
    // println!("g: {:?}", g);
    // println!("n1: {:?}, n2: {:?}, n3: {:?}", n1, n2, n3);
    // println!("Succs of n1: {:?}", g.predecessors(n2).unwrap().iter().map(|&n| g.node_data(n).unwrap()).collect::<Vec<&AstNode>>());
}