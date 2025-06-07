use gallagher_rfid_core::mifare::classic::{
    Error, FourBlockSector, KeyProvider, KeyType, Sector, Tag,
};

struct BruteForceAuthenticator {
    keys: Vec<[u8; 6]>,
}

impl KeyProvider for BruteForceAuthenticator {
    fn authenticate<T: Tag>(&self, tag: &mut T, sector: Sector) -> Result<(), Error> {
        for key in self.keys.iter() {
            match tag.authenticate(sector, key, KeyType::KeyB) {
                Ok(_) => return Ok(()),
                Err(_) => continue,
            }
        }
        Err(Error::AuthenticationFailed(FourBlockSector::S0.into()))
    }
}

pub fn wipe_mifare_classic<T: Tag>(tag: &mut T) {
    let auth_provider = BruteForceAuthenticator {
        keys: [
            [0xFFu8; 6],
            [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
            [0xB7, 0xBF, 0x0C, 0x13, 0x06, 0x6E],
        ]
        .into(),
    };
    let empty_data = [0u8; 16];
    let default_trailer = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF,
    ];

    for sector in Sector::iter() {
        if auth_provider.authenticate(tag, sector).is_ok() {
            // Write empty data, skipping last block.
            for block in sector.iter_blocks().take(3) {
                if u8::from(block) == 0u8 {
                    // Must skip writing manufacturer block
                    continue;
                }
                println!("Wiping {:?}", block);
                tag.write_block(block, empty_data).unwrap();
            }
            // Write trailer to first block
            tag.write_block(sector.iter_blocks().last().unwrap(), default_trailer)
                .unwrap();
        } else {
            println!("Failed wiping sector {:?}", sector);
        }
    }
}
