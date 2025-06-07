use gallagher_rfid_core::mifare::classic::{
    Error, FourBlockSector, KeyProvider, KeyType, Sector, Tag,
};

struct BruteForceAuthenticator {
    keys: Vec<[u8; 6]>,
    key_type: KeyType,
}

impl KeyProvider for BruteForceAuthenticator {
    fn authenticate<T: Tag>(&self, tag: &mut T, sector: Sector) -> Result<(), Error> {
        for key in self.keys.iter() {
            match tag.authenticate(sector, key, self.key_type) {
                Ok(_) => {
                    return {
                        println!("Authenticated to sector {sector:?} with key {key:?}");
                        Ok(())
                    }
                }
                Err(_) => continue,
            }
        }
        Err(Error::AuthenticationFailed(FourBlockSector::S0.into()))
    }
}

fn wipe_sector<T: Tag>(
    tag: &mut T,
    key_provider: &impl KeyProvider,
    sector: Sector,
) -> Result<(), Error> {
    let empty_data = [0u8; 16];
    let default_trailer = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF,
    ];

    key_provider.authenticate(tag, sector)?;

    // Write empty data, skipping last block.
    for block in sector.iter_blocks().take(3) {
        if u8::from(block) == 0u8 {
            // Must skip writing manufacturer block
            continue;
        }
        println!("Wiping block {:?}", block);
        tag.write_block(block, empty_data)?;
    }

    // Write trailer to first block
    tag.write_block(sector.iter_blocks().last().unwrap(), default_trailer)
}

pub fn wipe_mifare_classic<T: Tag>(tag: &mut T) {
    let auth_provider_a = BruteForceAuthenticator {
        key_type: KeyType::KeyA,
        keys: [
            [0xFFu8; 6],
            [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],
            [0x16, 0x0A, 0x91, 0xD2, 0x9A, 0x9C],
        ]
        .into(),
    };
    let auth_provider_b = BruteForceAuthenticator {
        key_type: KeyType::KeyB,
        keys: [
            [0xFFu8; 6],
            [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
            [0xB7, 0xBF, 0x0C, 0x13, 0x06, 0x6E],
        ]
        .into(),
    };

    for sector in Sector::iter() {
        println!("Wiping sector {:?}", sector);

        if let Err(e) = wipe_sector(tag, &auth_provider_a, sector) {
            println!("Failed wiping sector {:?} with key A: {e:?}.", sector);
            println!("Trying key B...");
            if let Err(e) = wipe_sector(tag, &auth_provider_b, sector) {
                println!("Failed wiping sector {:?} with key B: {e:?}.", sector);
            }
        }
    }
}
