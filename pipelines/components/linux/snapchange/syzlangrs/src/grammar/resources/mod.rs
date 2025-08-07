pub mod gen;

#[derive(Clone, Debug)]
pub struct ResourceDesc {
    pub id: usize,
    pub kind: &'static [ResourceDesc] // List of compatible resources
}
