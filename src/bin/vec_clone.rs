fn main() {
    let v: Vec<_> = "cn.bing.com".as_bytes().to_vec();
    
    let v2 = v.clone();
    println!("v.lens:{}", v.len());
    println!("v2.lens:{}", v2.len());

    for val in v2 {
         println!("{:02x}",val);
    }
   
}
