use std::time::Duration;

#[tokio::main]
async  fn main(){
    tokio::select! {
        _=long_time_task("1",20)=>{},
        _=long_time_task("2",5)=>{},
    }
}

async fn long_time_task(task_name:&str,sec:u8){
    println!("{} has started",task_name);
    tokio::time::sleep(Duration::from_secs(sec as u64)).await;
    println!("{} completed!",task_name);
}