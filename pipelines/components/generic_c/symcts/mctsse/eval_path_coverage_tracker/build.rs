use std::io::Result;
fn main() -> Result<()>{
    let path = "src/counts.proto";
    println!("cargo:rerun-if-changed={}", path);
    prost_build::compile_protos(&[path], &["src/"])?;
    Ok(())
}