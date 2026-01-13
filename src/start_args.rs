use std::path::PathBuf;
use clap::{Parser};

#[derive(Debug,Parser)]
pub struct StartArgs{
    config:Option<PathBuf>
}
impl StartArgs{
    pub fn config(&self)->Option<&PathBuf>{
        self.config.as_ref()
    }
}