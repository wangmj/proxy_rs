use hickory_resolver::{self, Resolver};
#[tokio::main]
async fn main() {
    let resolver = Resolver::builder_tokio().unwrap().build();
    let response = resolver.lookup_ip("www.baidu.com.").await.unwrap();
    // let ip= response.iter().next();
    for ip in response.iter(){
        println!("{}",ip);
    }
//    while let a=response.iter(){
//        println!("{:?}",ip);
    
//    }
}
