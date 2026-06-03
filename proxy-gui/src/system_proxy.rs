use anyhow::Result;

#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::sync::LazyLock;

#[cfg(windows)]
use winreg::{HKCU, enums::*};

pub fn enable_socks5_system_proxy(host: &str, port: u16) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums;

        let settings = HKCU.open_subkey_with_flags(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            enums::KEY_ALL_ACCESS,
        )?;
        settings.set_value("ProxyEnable", &1u32)?;
        let proxy_server = format!("socks5={}:{}", host, port);
        settings.set_value("ProxyServer", &proxy_server)?;
    }
    #[cfg(target_os = "macos")]
    {
        let service = &MACOS_ACTIVE_NETWORK_SERVICE;
        let status = Command::new("networksetup")
            .args(["-setsocksfirewallproxy", service, host, &port.to_string()])
            .status()?;
        if !status.success() {
            return Err(anyhow!("set proxy failed."));
        }
        let status = Command::new("networksetup")
            .args(["-setsocksfirewallproxystate", service, "on"])
            .status()?;
        if !status.success() {
            return Err(anyhow!("set proxy failed."));
        }
    }
    #[cfg(target_os = "linux")]
    {
        let status = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "manual"])
            .status()?;
        if !status.success() {
            return Err(anyhow!("set proxy failed."));
        }
        let status = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.socks", "host", host])
            .status()?;
        if !status.success() {
            return Err(anyhow!("set proxy failed."));
        }
        let status = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.socks", "port", &port.to_string()])
            .status()?;
        if !status.success() {
            return Err(anyhow!("set proxy failed."));
        }
    }

    Ok(())
    // todo!()
}

pub fn disalbe_socks5_system_proxy() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let settings = HKCU.open_subkey_with_flags(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            enums::KEY_ALL_ACCESS,
        )?;
        settings.set_value("ProxyEnable", &0u32)?;
        settings.set_value("ProxyServer", &"")?;
    }
    #[cfg(target_os = "macos")]
    {
        let service = &MACOS_ACTIVE_NETWORK_SERVICE;

        let status = Command::new("networksetup")
            .args(["-setsocksfirewallproxystate", service, "off"])
            .status()?;
        if !status.success() {
            return Err(anyhow!("set proxy failed."));
        }
    }
    #[cfg(target_os = "linux")]
    {
        let status = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "'none'"])
            .status()?;
        if !status.success() {
            return Err(anyhow!("set proxy failed."));
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
const MACOS_ACTIVE_NETWORK_SERVICE: LazyLock<String> = LazyLock::new(get_active_network_service);
#[cfg(target_os = "macos")]
fn get_active_network_service() -> String {
    let output = Command::new("route").args(["get default"]).output().expect("获取默认路由出错");
    let output_str = String::from_utf8_lossy(&output.stdout);
    let interface = output_str
        .lines()
        .find(|&l| l.trim().starts_with("interface:"))
        .and_then(|l| l.split_ascii_whitespace().nth(1))
        .unwrap_or("en0")
        .to_string();

    let output = Command::new("networksetup")
        .arg("-listnetworkserviceorder")
        .output()
        .expect("获取networksetup出错");

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut lines = output_str.lines().peekable();

    let full_interface = format!("Device: {interface}");
    let mut prev: Option<&str> = None;
    while let Some(line) = lines.next() {
        //匹配Device: en0的行，前一行就是
        if line.contains(&full_interface) {
            if let Some(s) = prev {
                let s = s.trim().split_ascii_whitespace().nth(1);
                return s.unwrap_or("Wi-Fi").to_string();
            }
        } else {
            prev = Some(line);
        }
    }
    "Wi-Fi".to_string()
}
