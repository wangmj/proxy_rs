use anyhow::{Result, anyhow};
use maxminddb::{Reader, geoip2::{Asn, City}};
use std::{env, net::IpAddr};

fn load_reader() -> Result<(Reader<Vec<u8>>, Reader<Vec<u8>>)> {
    let mut base_dir = env::current_dir()?;
    base_dir.push("geoips");
    let city_reader = Reader::open_readfile(base_dir.join("GeoLite2-City.mmdb"))?;
    let asn_reader = Reader::open_readfile(base_dir.join("GeoLite2-ASN.mmdb"))?;
    Ok((city_reader, asn_reader))
}
pub(crate) fn get_country(ip: &IpAddr) -> Result<String> {
    if let Ok((city_reader, _)) = load_reader() {
        let result = city_reader.lookup(*ip)?;
        match result.decode::<City>()? {
            Some(city) => match city.country.iso_code {
                Some(code) => Ok(code.to_string()),
                None => Ok("".to_string()),
            },
            None => Ok("".into()),
        }
    } else {
        Err(anyhow!("Load GeoIP City reader failed!"))
    }
}


pub(crate) fn get_asn(ip:&IpAddr)->Result<String>{
    if let Ok((_,asn_reader)) = load_reader(){
        let result=asn_reader.lookup(*ip)?;
        match result.decode::<Asn>()?{
            Some(asn) => {
                match asn.autonomous_system_number{
                    Some(num) => Ok(format!("AS{}",num)),
                    None => Ok("".into()),
                }
            },
            None => Ok("".into()),
        }
    }else{
        Err(anyhow!("Load GeoIp ASN Reader failed!"))
    }
}