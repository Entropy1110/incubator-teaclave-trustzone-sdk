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

use crate::alloc::string::ToString;
use optee_utee::property::{ClientIdentity, PropertyKey};
use optee_utee::{ErrorKind, LoginType, Result, Uuid};

const ENC_MNIST_TA_UUID: &str = proto::inference::UUID;
const SECURE_UPDATE_TA_UUID: &str = "00000073-6563-7572-655f-757064617465";

pub enum Policy {
    EncMnistOnly,
    EncMnistOrSecureUpdate,
}

fn parse_uuid(raw: &str) -> Result<Uuid> {
    let trimmed = raw.trim();
    Uuid::parse_str(trimmed)
}

fn caller_uuid() -> Result<Uuid> {
    let identity = ClientIdentity.get()?;
    if identity.login_type() != LoginType::TrustedApp {
        return Err(ErrorKind::AccessDenied.into());
    }
    Ok(identity.uuid())
}

pub fn ensure(policy: Policy) -> Result<()> {
    let caller = caller_uuid()?;
    match policy {
        Policy::EncMnistOnly => {
            let allowed = parse_uuid(ENC_MNIST_TA_UUID)?;
            let caller_str = caller.to_string();
            let allowed_str = allowed.to_string();
            if caller_str != allowed_str {
                return Err(ErrorKind::AccessDenied.into());
            }
        }
        Policy::EncMnistOrSecureUpdate => {
            let enc_mnist = parse_uuid(ENC_MNIST_TA_UUID)?;
            let secure_update = parse_uuid(SECURE_UPDATE_TA_UUID)?;
            let caller_str = caller.to_string();
            let enc_str = enc_mnist.to_string();
            let update_str = secure_update.to_string();
            if caller_str != enc_str && caller_str != update_str {
                return Err(ErrorKind::AccessDenied.into());
            }
        }
    }
    Ok(())
}
