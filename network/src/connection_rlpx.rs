// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    connection::{PacketAssembler, PacketWithLenAssembler},
    handshake::Handshake,
    Error, ErrorKind,
};
use bytes::BytesMut;
use cfx_types::{H128, H256, H512};
use crypto::{
    aessafe::AesSafe256Encryptor,
    blockmodes::{CtrMode, EcbEncryptor, EncPadding, NoPadding},
    buffer::{RefReadBuffer, RefWriteBuffer},
    symmetriccipher::{Decryptor, Encryptor},
};
use keccak_hash::{keccak, write_keccak};
use keylib::crypto::ecdh::agree;
use rlp::RlpStream;
use tiny_keccak::Keccak;

pub struct EncryptedPacketAssembler {
    /// Egress data encryptor
    encoder: CtrMode<AesSafe256Encryptor>,
    /// Ingress data decryptor
    decoder: CtrMode<AesSafe256Encryptor>,
    /// Ingress data decryptor
    mac_encoder: EcbEncryptor<AesSafe256Encryptor, EncPadding<NoPadding>>,
    /// MAC for egress data
    egress_mac: Keccak,
    /// MAC for ingress data
    ingress_mac: Keccak,

    /// Assembler to prefix packet with length
    length_assembler: PacketWithLenAssembler,
}

impl PacketAssembler for EncryptedPacketAssembler {
    fn is_oversized(&self, len: usize) -> bool {
        let encrypted_len = self.encrypted_len(len);
        self.length_assembler.is_oversized(encrypted_len)
    }

    fn assemble(&mut self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        let encrypted_data = self.encrypt(&data)?;
        self.length_assembler.assemble(encrypted_data)
    }

    fn load(&mut self, buf: &mut BytesMut) -> Result<Option<BytesMut>, Error> {
        let encrypted_data = match self.length_assembler.load(buf)? {
            Some(data) => data,
            None => return Ok(None),
        };

        Ok(Some(self.decrypt(encrypted_data)?))
    }
}

impl EncryptedPacketAssembler {
    const ENCRYPTED_HEADER_LEN: usize = 32;

    /// Create an encrypted connection out of the handshake.
    pub fn new(handshake: &Handshake) -> Result<Self, Error> {
        let shared =
            agree(handshake.ecdhe.secret(), &handshake.remote_ephemeral)?;

        let mut nonce_material = H512::new();
        if handshake.originated {
            handshake.remote_nonce.copy_to(&mut nonce_material[0..32]);
            handshake.nonce.copy_to(&mut nonce_material[32..64]);
        } else {
            handshake.nonce.copy_to(&mut nonce_material[0..32]);
            handshake.remote_nonce.copy_to(&mut nonce_material[32..64]);
        }

        let mut key_material = H512::new();
        shared.copy_to(&mut key_material[0..32]);
        write_keccak(&nonce_material, &mut key_material[32..64]);
        keccak(&key_material).copy_to(&mut key_material[32..64]);
        keccak(&key_material).copy_to(&mut key_material[32..64]);

        let iv = vec![0u8; 16];
        let encoder =
            CtrMode::new(AesSafe256Encryptor::new(&key_material[32..64]), iv);
        let iv = vec![0u8; 16];
        let decoder =
            CtrMode::new(AesSafe256Encryptor::new(&key_material[32..64]), iv);

        keccak(&key_material).copy_to(&mut key_material[32..64]);
        let mac_encoder = EcbEncryptor::new(
            AesSafe256Encryptor::new(&key_material[32..64]),
            NoPadding,
        );

        let mut egress_mac = Keccak::new_keccak256();
        let mut mac_material = H256::from_slice(&key_material[32..64])
            ^ handshake.remote_nonce.clone();
        egress_mac.update(&mac_material);
        egress_mac.update(
            if handshake.originated {
                &handshake.auth_cipher
            } else {
                &handshake.ack_cipher
            },
        );

        let mut ingress_mac = Keccak::new_keccak256();
        mac_material =
            H256::from_slice(&key_material[32..64]) ^ handshake.nonce.clone();
        ingress_mac.update(&mac_material);
        ingress_mac.update(
            if handshake.originated {
                &handshake.ack_cipher
            } else {
                &handshake.auth_cipher
            },
        );

        Ok(EncryptedPacketAssembler {
            encoder,
            decoder,
            mac_encoder,
            egress_mac,
            ingress_mac,
            length_assembler: PacketWithLenAssembler::default(),
        })
    }

    fn encrypted_len(&self, raw_len: usize) -> usize {
        let padding = (16 - (raw_len % 16)) % 16;
        32 + raw_len + padding + 16
    }

    fn encrypt(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let mut header = RlpStream::new();
        let len = payload.len();
        header.append_raw(&[(len >> 16) as u8, (len >> 8) as u8, len as u8], 1);
        header.append_raw(&[0xc2u8, 0x80u8, 0x80u8], 1);
        let mut header = header.out();
        let padding = (16 - (payload.len() % 16)) % 16;
        header.resize(16, 0u8);

        let mut packet = vec![0u8; 32 + payload.len() + padding + 16];
        self.encoder
            .encrypt(
                &mut RefReadBuffer::new(&header),
                &mut RefWriteBuffer::new(&mut packet),
                false,
            )
            .expect("Invalid length or padding");
        Self::update_mac(
            &mut self.egress_mac,
            &mut self.mac_encoder,
            &packet[0..16],
        );
        self.egress_mac.clone().finalize(&mut packet[16..32]);
        self.encoder
            .encrypt(
                &mut RefReadBuffer::new(payload),
                &mut RefWriteBuffer::new(&mut packet[32..(32 + len)]),
                padding == 0,
            )
            .expect("Invalid length or padding");
        if padding != 0 {
            let pad = [0u8; 16];
            self.encoder
                .encrypt(
                    &mut RefReadBuffer::new(&pad[0..padding]),
                    &mut RefWriteBuffer::new(
                        &mut packet[(32 + len)..(32 + len + padding)],
                    ),
                    true,
                )
                .expect("Invalid length or padding");
        }
        self.egress_mac.update(&packet[32..(32 + len + padding)]);
        Self::update_mac(
            &mut self.egress_mac,
            &mut self.mac_encoder,
            &[0u8; 0],
        );
        self.egress_mac
            .clone()
            .finalize(&mut packet[(32 + len + padding)..]);

        Ok(packet)
    }

    /// Decrypt and authenticate an incoming packet header.
    fn read_header(
        &mut self, header: BytesMut,
    ) -> Result<(usize, usize), Error> {
        Self::update_mac(
            &mut self.ingress_mac,
            &mut self.mac_encoder,
            &header[0..16],
        );
        let mac = &header[16..];
        let mut expected = H256::new();
        self.ingress_mac.clone().finalize(&mut expected);
        if mac != &expected[0..16] {
            debug!("failed to read RLPx header, mac of header[16..] mismatch with expected ingress_mac (hash[..16])");
            return Err(ErrorKind::Auth.into());
        }

        let mut hdec = H128::new();
        self.decoder
            .decrypt(
                &mut RefReadBuffer::new(&header[0..16]),
                &mut RefWriteBuffer::new(&mut hdec),
                false,
            )
            .expect("Invalid length or padding");

        let length = ((((hdec[0] as u32) << 8) + (hdec[1] as u32)) << 8)
            + (hdec[2] as u32);
        let padding = (16 - (length % 16)) % 16;
        let full_length = length + padding + 16;
        Ok((length as usize, full_length as usize))
    }

    /// Decrypt and authenticate packet payload.
    fn read_payload(
        &mut self, payload: BytesMut, payload_len: usize,
    ) -> Result<BytesMut, Error> {
        self.ingress_mac.update(&payload[0..payload.len() - 16]);
        Self::update_mac(
            &mut self.ingress_mac,
            &mut self.mac_encoder,
            &[0u8; 0],
        );
        let mac = &payload[(payload.len() - 16)..];
        let mut expected = H128::new();
        self.ingress_mac.clone().finalize(&mut expected);
        if mac != &expected[..] {
            debug!("failed to read RLPx payload, mac of payload[len-16..] mismatch with expected ingress_mac (H128)");
            return Err(ErrorKind::Auth.into());
        }

        let mut packet = vec![0u8; payload_len];
        self.decoder
            .decrypt(
                &mut RefReadBuffer::new(&payload[0..payload_len]),
                &mut RefWriteBuffer::new(&mut packet),
                false,
            )
            .expect("Invalid length or padding");
        let mut pad_buf = [0u8; 16];
        self.decoder
            .decrypt(
                &mut RefReadBuffer::new(
                    &payload[payload_len..(payload.len() - 16)],
                ),
                &mut RefWriteBuffer::new(&mut pad_buf),
                false,
            )
            .expect("Invalid length or padding");
        Ok(packet.into())
    }

    /// Update MAC after reading or writing any data.
    fn update_mac(
        mac: &mut Keccak,
        mac_encoder: &mut EcbEncryptor<
            AesSafe256Encryptor,
            EncPadding<NoPadding>,
        >,
        seed: &[u8],
    )
    {
        let mut prev = H128::new();
        mac.clone().finalize(&mut prev);
        let mut enc = H128::new();
        mac_encoder
            .encrypt(
                &mut RefReadBuffer::new(&prev),
                &mut RefWriteBuffer::new(&mut enc),
                true,
            )
            .expect("Error updating MAC");
        mac_encoder.reset();

        enc = enc
            ^ if seed.is_empty() {
                prev
            } else {
                H128::from_slice(seed)
            };
        mac.update(&enc);
    }

    fn decrypt(&mut self, mut data: BytesMut) -> Result<BytesMut, Error> {
        if data.len() < Self::ENCRYPTED_HEADER_LEN {
            info!(
                "failed to read rlpx header, invalid length = {}",
                data.len()
            );
            return Err(ErrorKind::Auth.into());
        }

        let header = data.split_to(Self::ENCRYPTED_HEADER_LEN);
        let (payload_len, full_len) = self.read_header(header)?;

        if data.len() != full_len {
            info!(
                "failed to read rlpx payload, invalid length = {}, expected = {}",
                data.len(),
                full_len
            );
            return Err(ErrorKind::Auth.into());
        }

        Ok(self.read_payload(data, payload_len)?)
    }
}
