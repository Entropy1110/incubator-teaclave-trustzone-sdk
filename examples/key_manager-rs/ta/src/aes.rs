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

use optee_utee::{
    AlgorithmId, AttributeId, AttributeMemref, Cipher, ErrorKind, OperationMode, Result,
    TransientObject, TransientObjectType,
};

pub fn encrypt_chunk(
    key: &[u8; 32],
    iv: &[u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    if input.len() % 16 != 0 {
        return Err(ErrorKind::BadParameters.into());
    }
    if output.len() < input.len() {
        return Err(ErrorKind::ShortBuffer.into());
    }

    let mut key_object = TransientObject::allocate(TransientObjectType::Aes, 256)?;
    let cipher = Cipher::allocate(AlgorithmId::AesCbcNopad, OperationMode::Encrypt, 256)?;

    let attr = AttributeMemref::from_ref(AttributeId::SecretValue, key);
    key_object.populate(&[attr.into()])?;

    cipher.set_key(&key_object)?;
    cipher.init(iv);

    cipher.update(input, &mut output[..input.len()])
}

pub fn decrypt_chunk(
    key: &[u8; 32],
    iv: &[u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    if input.len() % 16 != 0 {
        return Err(ErrorKind::BadParameters.into());
    }
    if output.len() < input.len() {
        return Err(ErrorKind::ShortBuffer.into());
    }

    let mut key_object = TransientObject::allocate(TransientObjectType::Aes, 256)?;
    let cipher = Cipher::allocate(AlgorithmId::AesCbcNopad, OperationMode::Decrypt, 256)?;

    let attr = AttributeMemref::from_ref(AttributeId::SecretValue, key);
    key_object.populate(&[attr.into()])?;

    cipher.set_key(&key_object)?;
    cipher.init(iv);

    cipher.update(input, &mut output[..input.len()])
}
