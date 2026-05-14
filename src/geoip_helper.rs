use anyhow::Result;
use maxminddb::{
    Reader,
    geoip2::{Asn, City},
};
use std::{env, net::IpAddr, sync::LazyLock};

pub(crate) static GEOIP_READER: LazyLock<GeoipReader> =
    LazyLock::new(|| GeoipReader::open_from_file().expect("open geoIp reader failed!"));

pub struct GeoipReader {
    city_reader: Reader<Vec<u8>>,
    asn_reader: Reader<Vec<u8>>,
}
impl GeoipReader {
    fn open_from_file() -> Result<Self> {
        let mut base_dir = env::current_dir()?;
        base_dir.push("geoips");
        let city_reader = Reader::open_readfile(base_dir.join("GeoLite2-City.mmdb"))?;
        let asn_reader = Reader::open_readfile(base_dir.join("GeoLite2-ASN.mmdb"))?;
        Ok(Self {
            city_reader,
            asn_reader,
        })
    }

    pub(crate) fn get_country(&self, ip: &IpAddr) -> Result<String> {
        let result = self.city_reader.lookup(*ip)?;
        match result.decode::<City>()? {
            Some(city) => match city.country.iso_code {
                Some(code) => Ok(code.to_string()),
                None => Ok("".to_string()),
            },
            None => Ok("".into()),
        }
    }

    pub(crate) fn get_asn(&self, ip: &IpAddr) -> Result<String> {
        let result = self.asn_reader.lookup(*ip)?;
        match result.decode::<Asn>()? {
            Some(asn) => match asn.autonomous_system_number {
                Some(num) => Ok(format!("AS{}", num)),
                None => Ok("".into()),
            },
            None => Ok("".into()),
        }
    }
}
