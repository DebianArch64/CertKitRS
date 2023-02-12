use std::{fs::File, io::Read};

use openssl::{pkcs12::{self, Pkcs12}, x509::{X509Ref, X509}, nid::Nid, asn1::{Asn1TimeRef, Asn1Time}};

use crate::error::SigleError;

pub struct Cert {
    pub is_expired: bool,
    pub serial_number: String,
    pub team_id: String
}

impl std::fmt::Display for Cert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(isExpired: {}, serialNumber: {}, teamID: {})",self.is_expired,self.serial_number,self.team_id)
    }
}

const CERT_PASS: &str = ""; // generally empty. Mostly because ldid only takes in an empty string pass certificate lol

impl Cert {
    pub fn init(path: &str) -> Result<Cert,SigleError> {
        if path.ends_with("p12") {
            return Cert::from_pkcs12(path);
        } else if path.ends_with("pem") {
            return Cert::from_pem(path);
        }
        return Err(SigleError::new("unhandled certificate type."))
    }

    fn from_x509(cert: &X509Ref) -> Result<Cert,SigleError> {
        let team_id = match cert.subject_name().entries_by_nid(Nid::ORGANIZATIONALUNITNAME).last() {
            Some(val) => match val.data().as_utf8() {
                Ok(val) => val.to_string(),
                Err(err) => return Err(SigleError::new(err)),
            },
            None => return Err(SigleError::new("Failed getting common name.".to_string())),
        };

        let serial_number = match cert.serial_number().to_bn() {
            Ok(val) => match val.to_hex_str() { // Traditionally serial number is stored as a hex string even by Apple APIs !
                Ok(val) => val.to_string(),
                Err(err) => return Err(SigleError::new(err)),
            },
            Err(err) => return Err(SigleError::new(err)),
        };

        let binding = Asn1Time::days_from_now(0);
        let now = match &binding {
            Ok(val) => val,
            Err(_) => return Err(SigleError::new("Failed getting current time")),
        };
        let is_expired = match now.diff(cert.not_after()) {
            Ok(val) => val.days < 0,
            Err(err) => return Err(SigleError::new(err)),
        };
        return Ok(Cert{is_expired:is_expired,serial_number:serial_number,team_id:team_id});
    }

    fn from_pkcs12(path: &str) -> Result<Cert,SigleError> {
        let mut file = match File::open(path) {
            Ok(val) => val,
            Err(err) => return Err(SigleError::new(err)),
        };
        let mut der: Vec<u8> = Vec::new();
        let _ = match file.read_to_end(&mut der) {
            Ok(val) => val,
            Err(err) => return Err(SigleError::new(err)),
        };

        let dec = match pkcs12::Pkcs12::from_der(&der) {
            Ok(val) => val,
            Err(err) => return Err(SigleError::new(err)),
        };
        let p12 = match dec.parse(CERT_PASS) {
            Ok(val) => val,
            Err(err) => return Err(SigleError::new(err)),
        };

        return Cert::from_x509(&p12.cert);
    }

    fn from_pem(path: &str) -> Result<Cert,SigleError> {
        let mut file = match File::open(path) {
            Ok(val) => val,
            Err(err) => return Err(SigleError::new(err)),
        };
        let mut der: Vec<u8> = Vec::new();
        let _ = match file.read(&mut der) {
            Ok(val) => val,
            Err(err) => return Err(SigleError::new(err)),
        };

        let cert = match X509::from_pem(&der) {
            Ok(val) => val,
            Err(err) => return Err(SigleError::new(err)),
        };
        return Cert::from_x509(&cert);
    }
}