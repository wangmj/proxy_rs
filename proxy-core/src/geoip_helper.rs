use anyhow::{Result, anyhow};
use maxminddb::{
    Reader,
    geoip2::{Asn, City},
};
use std::{env, net::IpAddr, sync::LazyLock};

pub(crate) static GEOIP_READER: LazyLock<GeoipReader> =
    LazyLock::new(|| match GeoipReader::open_from_file() {
        Ok(r) => r,
        Err(err) => {
            log::error!("open geoIp reader failed! {err}");
            panic!()
        }
    });

pub struct GeoipReader {
    city_reader: Reader<Vec<u8>>,
    asn_reader: Reader<Vec<u8>>,
}
impl GeoipReader {
    fn open_from_file() -> Result<Self> {
        let base_dir = env::current_exe()?;

        let target_file =
            base_dir.parent().ok_or_else(|| anyhow!("get parent folder failed!"))?.join("geoips");
        let city_reader = Reader::open_readfile(target_file.join("GeoLite2-City.mmdb"))?;
        let asn_reader = Reader::open_readfile(target_file.join("GeoLite2-ASN.mmdb"))?;
        Ok(Self { city_reader, asn_reader })
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
