#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod mifare;
pub mod transport;
pub use transport::RfidTransport;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
