use async_trait::async_trait;

#[async_trait]
pub trait InBoundProxy:Sync+Send{
    async fn start(&self);
    async fn stop(&self);
}