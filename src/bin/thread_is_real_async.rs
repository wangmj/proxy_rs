use anyhow::Result;
use std::time::Duration;

///
/// 经过验证，确实是多线程处理的，同代码分析一致。
/// 在async_task方法调用时，后面的await只会等待该async_task调用成功，也就是说async_task方法内的线程创建成功就会返回，而不关心线程内的执行是否完成
fn main() -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(multi_task_starter());
    Ok(())
}

async fn multi_task_starter() {
    for i in 1u8..100 {
        async_task(i).await;
    }
}

async fn async_task(i: u8) {
    tokio::spawn(async move {
        println!("{} starting", i);
        tokio::time::sleep(Duration::from_secs(1)).await;
        println!("stopping {}", i);
    });
    println!("has creating {}", i);
}
