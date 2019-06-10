use crate::crypt::{gen_salsa_key, KeyPair};
use crate::packet::PoePacket;
use crate::Error;
use std::collections::HashMap;

pub struct Decrypter {
    keystore: HashMap<u32, KeyPair>,
}

impl Decrypter {
    pub fn new() -> Self {
        Decrypter {
            keystore: HashMap::new(),
        }
    }

    pub fn add_keypair(&mut self, buffer1: &[u8], buffer2: &[u8]) -> Result<(), crate::Error> {
        if buffer1.len() != 64 || buffer2.len() != 64 {
            return Err(crate::Error::KeyWrongSize);
        }

        let (key1, iv_sender) = gen_salsa_key(buffer1);
        let (key2, iv_receiver) = gen_salsa_key(buffer2);

        if key1 != key2 {
            return Err(crate::Error::KeyDiffer);
        }

        let keypair = KeyPair {
            key: key1,
            iv_sender,
            iv_receiver,
        };

        let mut exists = false;
        for kp in self.keystore.values() {
            if *kp == keypair {
                exists = true;
            }
        }

        if exists {
            return Err(Error::WrongKey);
        }

        self.keystore.insert(0, keypair);
        log::info!("Inserted new 0 keypair");

        Ok(())
    }

    pub fn process(&mut self, packet: &mut PoePacket) -> Result<(), Error> {
        Ok(())
    }
}
