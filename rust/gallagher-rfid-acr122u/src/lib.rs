use gallagher_rfid_core::{transport::RfidTransport, error::RfidError};

pub fn add(left: u64, right: u64) -> u64 {
    return 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
