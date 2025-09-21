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
    DataFlag, ErrorKind, GenericObject, ObjectStorageConstants, PersistentObject, Result,
};
use proto::key_manager::{AES_KEY_OBJECT_ID, AES_KEY_SIZE, RSA_KEY_OBJECT_ID};

pub fn store_aes_key(key: &[u8; AES_KEY_SIZE]) -> Result<()> {
    let mut obj_id = AES_KEY_OBJECT_ID.to_vec();
    let flags = DataFlag::ACCESS_WRITE
        | DataFlag::ACCESS_READ
        | DataFlag::ACCESS_WRITE_META
        | DataFlag::OVERWRITE;
    let init: [u8; 0] = [];
    let mut object = PersistentObject::create(
        ObjectStorageConstants::Private,
        obj_id.as_mut_slice(),
        flags,
        None,
        &init,
    )?;
    object.write(key)?;
    Ok(())
}

pub fn load_aes_key() -> Result<[u8; AES_KEY_SIZE]> {
    let mut obj_id = AES_KEY_OBJECT_ID.to_vec();
    let object = PersistentObject::open(
        ObjectStorageConstants::Private,
        obj_id.as_mut_slice(),
        DataFlag::ACCESS_READ,
    )?;
    let info = object.info()?;
    if info.data_size() != AES_KEY_SIZE {
        return Err(ErrorKind::CorruptObject.into());
    }
    let mut buffer = [0u8; AES_KEY_SIZE];
    let read = object.read(&mut buffer)? as usize;
    if read != AES_KEY_SIZE {
        return Err(ErrorKind::CorruptObject.into());
    }
    Ok(buffer)
}

pub fn aes_key_exists() -> bool {
    let mut obj_id = AES_KEY_OBJECT_ID.to_vec();
    PersistentObject::open(
        ObjectStorageConstants::Private,
        obj_id.as_mut_slice(),
        DataFlag::ACCESS_READ,
    )
    .is_ok()
}

pub fn store_rsa_components(blob: &[u8]) -> Result<()> {
    let mut obj_id = RSA_KEY_OBJECT_ID.to_vec();
    let flags = DataFlag::ACCESS_WRITE
        | DataFlag::ACCESS_READ
        | DataFlag::ACCESS_WRITE_META
        | DataFlag::OVERWRITE;
    let init: [u8; 0] = [];
    let mut object = PersistentObject::create(
        ObjectStorageConstants::Private,
        obj_id.as_mut_slice(),
        flags,
        None,
        &init,
    )?;
    object.write(blob)?;
    Ok(())
}

pub fn load_rsa_components() -> Result<Vec<u8>> {
    let mut obj_id = RSA_KEY_OBJECT_ID.to_vec();
    let object = PersistentObject::open(
        ObjectStorageConstants::Private,
        obj_id.as_mut_slice(),
        DataFlag::ACCESS_READ,
    )?;
    let info = object.info()?;
    let mut buffer = vec![0u8; info.data_size()];
    let read = object.read(&mut buffer)? as usize;
    if read != buffer.len() {
        return Err(ErrorKind::CorruptObject.into());
    }
    Ok(buffer)
}
