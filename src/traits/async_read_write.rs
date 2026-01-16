use tokio::io::{AsyncRead, AsyncWrite};


pub  trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}
