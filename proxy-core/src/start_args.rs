use std::path::PathBuf;
use clap::{Parser};

#[derive(Debug,Parser)]
pub struct StartArgs{
    #[arg(short,long,help="config file path")]
    config:Option<PathBuf>
}
impl StartArgs{
    pub fn config(&self)->Option<&PathBuf>{
        self.config.as_ref()
    }
}