pub trait RfidTransport {
    fn transceive(&mut self, req: &[u8], resp: &mut [u8]) -> Result<usize, crate::error::RfidError>;
}