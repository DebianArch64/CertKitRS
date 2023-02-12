use std::{fmt, error::Error};

#[derive(Debug)]
pub struct SigleError {
    details: String
}

impl SigleError {
    pub fn new<T:std::string::ToString>(msg: T) -> SigleError {
        SigleError{details: msg.to_string()}
    }
}

impl fmt::Display for SigleError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.details)
    }
}

impl Error for SigleError {
    fn description(&self) -> &str {
        &self.details
    }
}