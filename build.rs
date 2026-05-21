use std::{env, error::Error, fs, path::{Path}};

fn main() {
    // 要复制的源文件（比如根目录下的 config.toml）
    let geoip_dir="geoips";
    let client_json_config="examples/config/client.json";
    let server_json_config="examples/config/server.json";
   
    // 获取 target 目录路径
    let out_dir = env::var("OUT_DIR").unwrap();
    // target/debug 或 target/release
    let target_dir = Path::new(&out_dir)
        .parent().unwrap()  // 跳出 build 目录
        .parent().unwrap()
        .parent().unwrap(); // 跳出 deps 目录

    // 复制文件
    copy_dir_all(geoip_dir, &target_dir.join(geoip_dir)).unwrap();
    let _= fs::copy(client_json_config, target_dir.join("client.json"));
    let _= fs::copy(server_json_config, target_dir.join("server.json"));

    // 告诉 Cargo：源文件变化时重新编译
    println!("cargo:rerun-if-changed={}", geoip_dir);
}

fn copy_dir_all(src_path:impl AsRef<Path>,dest_path:&Path)->Result<(),Box<dyn Error>>{
   
    fs::create_dir_all(dest_path)?;
    for entry in  fs::read_dir(src_path)?{
        let entry=entry?;
        let filetype= entry.file_type()?;
        println!("file type: {:?}",filetype);
        let dest_file_path=&dest_path.join(entry.file_name());
        println!("src path: {}, dest path: {} ",entry.path().display(),dest_file_path.display());
        
        if filetype.is_dir(){
            println!("file type is dir, entry path: {}",entry.path().display());
            copy_dir_all(entry.path(),dest_file_path)?;
        }else{
            eprintln!("{}",entry.path().display());
            fs::copy(entry.path(), dest_file_path)?;
        }
    }

    Ok(())
}