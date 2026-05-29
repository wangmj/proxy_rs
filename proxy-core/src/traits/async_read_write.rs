use tokio::io::{AsyncRead, AsyncWrite};


pub  trait AsyncReadWrite: AsyncRead + AsyncWrite+Send+Sync+'static {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite+Send+Sync+'static {}
