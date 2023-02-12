mod cert;
mod error;

#[cfg(test)]
mod tests {
    use crate::cert::Cert;

    use super::*;

    #[test]
    fn main() {
        let yes = Cert::init("cert.p12").expect("msg");
        println!("{}", yes);
    }
}
