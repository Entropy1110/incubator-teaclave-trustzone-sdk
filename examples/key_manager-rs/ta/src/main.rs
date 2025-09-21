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

#![no_std]
#![no_main]

extern crate alloc;

use aes::{decrypt_chunk as aes_decrypt_chunk, encrypt_chunk as aes_encrypt_chunk};
use auth::{ensure, Policy};
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{ErrorKind, Parameters, Random, Result};
use proto::key_manager;
use rsa::{generate_keypair, RsaComponents};
use spin::Mutex;
use storage::{
    aes_key_exists, load_aes_key, load_rsa_components, store_aes_key, store_rsa_components,
};

mod aes;
mod auth;
mod rsa;
mod storage;

static AES_KEY_CACHE: Mutex<Option<[u8; key_manager::AES_KEY_SIZE]>> = Mutex::new(None);
static RSA_KEY_CACHE: Mutex<Option<RsaComponents>> = Mutex::new(None);

#[ta_create]
fn create() -> Result<()> {
    trace_println!("[+] Key manager TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters) -> Result<()> {
    trace_println!("[+] Key manager TA open session");
    Ok(())
}

#[ta_close_session]
fn close_session() {
    trace_println!("[+] Key manager TA close session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("[+] Key manager TA destroy");
}

#[ta_invoke_command]
fn invoke_command(cmd_id: u32, params: &mut Parameters) -> Result<()> {
    trace_println!("[+] Key manager invoke command: {}", cmd_id);
    match cmd_id {
        0 => generate_aes_key(params),
        1 => import_aes_key(params),
        2 => export_aes_key(params),
        3 => encrypt_aes_chunk(params),
        4 => decrypt_aes_chunk(params),
        5 => generate_random_bytes(params),
        6 => has_aes_key(params),
        7 => generate_rsa_key(params),
        8 => import_rsa_key(params),
        9 => export_rsa_public(params),
        _ => Err(ErrorKind::NotSupported.into()),
    }
}

fn update_aes_cache(key: [u8; key_manager::AES_KEY_SIZE]) {
    let mut cache = AES_KEY_CACHE.lock();
    cache.replace(key);
}

fn load_cached_aes_key() -> Result<[u8; key_manager::AES_KEY_SIZE]> {
    let mut cache = AES_KEY_CACHE.lock();
    if let Some(key) = *cache {
        return Ok(key);
    }
    let key = load_aes_key()?;
    cache.replace(key);
    Ok(key)
}

fn update_rsa_cache(components: RsaComponents) {
    let mut cache = RSA_KEY_CACHE.lock();
    cache.replace(components);
}

fn load_cached_rsa_components() -> Result<RsaComponents> {
    let mut cache = RSA_KEY_CACHE.lock();
    if let Some(ref components) = *cache {
        return Ok(components.clone());
    }
    let blob = load_rsa_components()?;
    let components = RsaComponents::deserialize(&blob)?;
    cache.replace(components.clone());
    Ok(components)
}

fn generate_aes_key(_params: &mut Parameters) -> Result<()> {
    ensure(Policy::EncMnistOnly)?;
    let mut key = [0u8; key_manager::AES_KEY_SIZE];
    Random::generate(&mut key);
    store_aes_key(&key)?;
    update_aes_cache(key);
    trace_println!("[+] Generated new AES key");
    Ok(())
}

fn import_aes_key(params: &mut Parameters) -> Result<()> {
    ensure(Policy::EncMnistOnly)?;
    let mut p0 = unsafe { params.0.as_memref()? };
    let data = p0.buffer();
    if data.len() != key_manager::AES_KEY_SIZE {
        return Err(ErrorKind::BadParameters.into());
    }
    let mut key = [0u8; key_manager::AES_KEY_SIZE];
    key.copy_from_slice(&data[..key_manager::AES_KEY_SIZE]);
    store_aes_key(&key)?;
    update_aes_cache(key);
    trace_println!("[+] Imported AES key");
    Ok(())
}

fn export_aes_key(params: &mut Parameters) -> Result<()> {
    ensure(Policy::EncMnistOrSecureUpdate)?;
    let mut p0 = unsafe { params.0.as_memref()? };
    let key = load_cached_aes_key()?;
    {
        let buffer = p0.buffer();
        if buffer.len() < key.len() {
            return Err(ErrorKind::ShortBuffer.into());
        }
        buffer[..key.len()].copy_from_slice(&key);
    }
    p0.set_updated_size(key.len());
    trace_println!("[+] Exported AES key");
    Ok(())
}

fn encrypt_aes_chunk(params: &mut Parameters) -> Result<()> {
    ensure(Policy::EncMnistOnly)?;
    let mut p0 = unsafe { params.0.as_memref()? };
    let mut p1 = unsafe { params.1.as_memref()? };
    let mut p2 = unsafe { params.2.as_memref()? };

    let mut next_iv = [0u8; key_manager::AES_BLOCK_SIZE];
    let written = {
        let input = p0.buffer();
        let output = p1.buffer();
        let iv_buf = p2.buffer();

        if iv_buf.len() < key_manager::AES_BLOCK_SIZE {
            return Err(ErrorKind::BadParameters.into());
        }
        if output.len() < input.len() {
            return Err(ErrorKind::ShortBuffer.into());
        }

        let key = load_cached_aes_key()?;
        let mut iv = [0u8; key_manager::AES_BLOCK_SIZE];
        iv.copy_from_slice(&iv_buf[..key_manager::AES_BLOCK_SIZE]);

        let written_len = aes_encrypt_chunk(&key, &iv, input, output)?;

        if written_len != input.len() {
            return Err(ErrorKind::Generic.into());
        }
        if written_len < key_manager::AES_BLOCK_SIZE {
            return Err(ErrorKind::BadParameters.into());
        }
        next_iv.copy_from_slice(&output[written_len - key_manager::AES_BLOCK_SIZE..written_len]);
        written_len
    };

    p1.set_updated_size(written);

    {
        let iv_buf = p2.buffer();
        iv_buf[..key_manager::AES_BLOCK_SIZE].copy_from_slice(&next_iv);
    }
    p2.set_updated_size(key_manager::AES_BLOCK_SIZE);
    Ok(())
}

fn decrypt_aes_chunk(params: &mut Parameters) -> Result<()> {
    ensure(Policy::EncMnistOnly)?;
    let mut p0 = unsafe { params.0.as_memref()? };
    let mut p1 = unsafe { params.1.as_memref()? };
    let mut p2 = unsafe { params.2.as_memref()? };

    let mut next_iv = [0u8; key_manager::AES_BLOCK_SIZE];
    let written = {
        let input = p0.buffer();
        let output = p1.buffer();
        let iv_buf = p2.buffer();

        if iv_buf.len() < key_manager::AES_BLOCK_SIZE {
            return Err(ErrorKind::BadParameters.into());
        }
        if input.len() % key_manager::AES_BLOCK_SIZE != 0 {
            return Err(ErrorKind::BadParameters.into());
        }
        if output.len() < input.len() {
            return Err(ErrorKind::ShortBuffer.into());
        }
        if input.is_empty() {
            return Err(ErrorKind::BadParameters.into());
        }

        let key = load_cached_aes_key()?;
        let mut iv = [0u8; key_manager::AES_BLOCK_SIZE];
        iv.copy_from_slice(&iv_buf[..key_manager::AES_BLOCK_SIZE]);

        let next_iv_offset = input.len() - key_manager::AES_BLOCK_SIZE;
        next_iv.copy_from_slice(&input[next_iv_offset..]);

        let written_len = aes_decrypt_chunk(&key, &iv, input, output)?;
        if written_len != input.len() {
            return Err(ErrorKind::Generic.into());
        }
        written_len
    };

    p1.set_updated_size(written);
    {
        let iv_buf = p2.buffer();
        iv_buf[..key_manager::AES_BLOCK_SIZE].copy_from_slice(&next_iv);
    }
    p2.set_updated_size(key_manager::AES_BLOCK_SIZE);
    Ok(())
}

fn generate_random_bytes(params: &mut Parameters) -> Result<()> {
    ensure(Policy::EncMnistOnly)?;
    let mut p0 = unsafe { params.0.as_memref()? };
    let size = {
        let buffer = p0.buffer();
        if buffer.is_empty() {
            return Err(ErrorKind::BadParameters.into());
        }
        Random::generate(buffer);
        buffer.len()
    };
    p0.set_updated_size(size);
    Ok(())
}

fn has_aes_key(params: &mut Parameters) -> Result<()> {
    ensure(Policy::EncMnistOrSecureUpdate)?;
    let mut p0 = unsafe { params.0.as_value()? };
    let exists = aes_key_exists();
    p0.set_a(if exists { 1 } else { 0 });
    p0.set_b(0);
    Ok(())
}

fn generate_rsa_key(_params: &mut Parameters) -> Result<()> {
    ensure(Policy::EncMnistOnly)?;
    let components = generate_keypair(2048)?;
    let blob = components.serialize();
    store_rsa_components(&blob)?;
    update_rsa_cache(components);
    trace_println!("[+] Generated RSA keypair");
    Ok(())
}

fn import_rsa_key(params: &mut Parameters) -> Result<()> {
    ensure(Policy::EncMnistOnly)?;
    let mut p0 = unsafe { params.0.as_memref()? };
    let data = p0.buffer();
    let components = RsaComponents::deserialize(data)?;
    let blob = components.serialize();
    store_rsa_components(&blob)?;
    update_rsa_cache(components);
    trace_println!("[+] Imported RSA key material");
    Ok(())
}

fn export_rsa_public(params: &mut Parameters) -> Result<()> {
    ensure(Policy::EncMnistOrSecureUpdate)?;
    let components = load_cached_rsa_components()?;
    let mut p0 = unsafe { params.0.as_memref()? };
    let written = 4 + components.modulus.len() + 4 + components.public_exponent.len();
    {
        let buffer = p0.buffer();
        if buffer.len() < written {
            return Err(ErrorKind::ShortBuffer.into());
        }
        let mut offset = 0;
        let n_len = components.modulus.len() as u32;
        buffer[offset..offset + 4].copy_from_slice(&n_len.to_le_bytes());
        offset += 4;
        buffer[offset..offset + components.modulus.len()].copy_from_slice(&components.modulus);
        offset += components.modulus.len();
        let e_len = components.public_exponent.len() as u32;
        buffer[offset..offset + 4].copy_from_slice(&e_len.to_le_bytes());
        offset += 4;
        buffer[offset..offset + components.public_exponent.len()]
            .copy_from_slice(&components.public_exponent);
    }
    p0.set_updated_size(written);
    trace_println!("[+] Exported RSA public key");
    Ok(())
}

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
