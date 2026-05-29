use async_trait::async_trait;

#[async_trait]
pub trait InBoundProxy{
    async fn start(&self);
}