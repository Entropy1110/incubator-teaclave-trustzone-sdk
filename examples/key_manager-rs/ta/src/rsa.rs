// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

extern crate alloc;

use alloc::{vec, vec::Vec};
use optee_utee::{
    AttributeId, ErrorKind, GenericObject, Result, TransientObject, TransientObjectType,
};

#[derive(Clone)]
pub struct RsaComponents {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
    pub private_exponent: Vec<u8>,
}

impl RsaComponents {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            4 + self.modulus.len()
                + 4
                + self.public_exponent.len()
                + 4
                + self.private_exponent.len(),
        );
        out.extend_from_slice(&(self.modulus.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.modulus);
        out.extend_from_slice(&(self.public_exponent.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.public_exponent);
        out.extend_from_slice(&(self.private_exponent.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.private_exponent);
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(ErrorKind::BadParameters.into());
        }
        let (n_len_bytes, rest) = data.split_at(4);
        let mut n_len_buf = [0u8; 4];
        n_len_buf.copy_from_slice(n_len_bytes);
        let n_len = u32::from_le_bytes(n_len_buf) as usize;
        if rest.len() < n_len + 4 {
            return Err(ErrorKind::BadParameters.into());
        }
        let (modulus, rest) = rest.split_at(n_len);
        let (e_len_bytes, rest) = rest.split_at(4);
        let mut e_len_buf = [0u8; 4];
        e_len_buf.copy_from_slice(e_len_bytes);
        let e_len = u32::from_le_bytes(e_len_buf) as usize;
        if rest.len() < e_len + 4 {
            return Err(ErrorKind::BadParameters.into());
        }
        let (public_exponent, rest) = rest.split_at(e_len);
        let (d_len_bytes, rest) = rest.split_at(4);
        let mut d_len_buf = [0u8; 4];
        d_len_buf.copy_from_slice(d_len_bytes);
        let d_len = u32::from_le_bytes(d_len_buf) as usize;
        if rest.len() < d_len {
            return Err(ErrorKind::BadParameters.into());
        }
        let private_exponent = &rest[..d_len];

        Ok(Self {
            modulus: modulus.to_vec(),
            public_exponent: public_exponent.to_vec(),
            private_exponent: private_exponent.to_vec(),
        })
    }
}

pub fn generate_keypair(bits: usize) -> Result<RsaComponents> {
    if bits > 4096 {
        return Err(ErrorKind::BadParameters.into());
    }
    let key = TransientObject::allocate(TransientObjectType::RsaKeypair, bits)?;
    key.generate_key(bits, &[])?;

    let mut modulus = vec![0u8; bits / 8];
    let n_len = key.ref_attribute(AttributeId::RsaModulus, &mut modulus)?;
    modulus.truncate(n_len);

    let mut public_exponent = vec![0u8; 8];
    let e_len = key.ref_attribute(AttributeId::RsaPublicExponent, &mut public_exponent)?;
    public_exponent.truncate(e_len);

    let mut private_exponent = vec![0u8; bits / 8];
    let d_len = key.ref_attribute(AttributeId::RsaPrivateExponent, &mut private_exponent)?;
    private_exponent.truncate(d_len);

    Ok(RsaComponents {
        modulus,
        public_exponent,
        private_exponent,
    })
}
