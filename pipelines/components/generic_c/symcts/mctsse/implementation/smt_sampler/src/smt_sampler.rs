pub trait SmtSampler {
    fn sample(&self, ctx: &Context) -> Result<SymCCModel, String>;
}