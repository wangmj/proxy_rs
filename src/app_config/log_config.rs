use anyhow::Result;
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LogConfig {
    access: AccessLogConfig,
    // error: ErrorLogConfig,
}
impl LogConfig {
    pub fn level(&self) -> Result<log::Level> {
        let level = log::Level::from_str(self.access.level.to_lowercase().as_str())?;
        Ok(level)
    }
    pub fn level_filter(&self) -> Result<log::LevelFilter> {
        let lf = log::LevelFilter::from_str(self.access.level.to_lowercase().as_str())?;
        Ok(lf)
    }
    pub fn access_path(&self) -> &Path {
        self.access.path.as_path()
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AccessLogConfig {
    level: String,
    path: PathBuf,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ErrorLogConfig {
    path: PathBuf,
}
