use std::{env, path::{Path, PathBuf}};

pub fn expand_path(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if raw == "~" || raw.starts_with("~/") {
        if let Some(home) = env::var_os("HOME") {
            let mut expanded = PathBuf::from(home);
            if raw.len() > 2 {
                expanded.push(&raw[2..]);
            }
            return expanded;
        }
    } else if let Some(stripped) = raw.strip_prefix("./") {
        let mut currentdir = env::current_dir().expect("get current dir failed!");
        currentdir.push(stripped);
        return currentdir;
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_path_test() {
        let final_path = expand_path(Path::new("./file.json"));
        assert!(final_path.display().to_string().chars().count() > "/file.json".chars().count());
        println!("{}", final_path.display());
    }
}
