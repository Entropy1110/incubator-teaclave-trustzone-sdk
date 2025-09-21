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

use optee_teec::{
    Context, Error, ErrorKind, Operation, ParamNone, ParamTmpRef, ParamType, ParamValue, Session,
    Uuid,
};
use proto::key_manager::{self, Command, AES_KEY_SIZE};

fn parse_uuid() -> optee_teec::Result<Uuid> {
    Uuid::parse_str(key_manager::UUID.trim()).map_err(|_| Error::from(ErrorKind::BadParameters))
}

fn expect_access_denied<F>(label: &str, mut f: F) -> optee_teec::Result<()>
where
    F: FnMut() -> optee_teec::Result<()>,
{
    match f() {
        Err(err) if err.kind() == ErrorKind::AccessDenied => {
            println!("{}: access denied as expected", label);
            Ok(())
        }
        Err(err) => {
            println!(
                "{}: unexpected error {:?} (code: 0x{:x})",
                label,
                err.kind(),
                err.raw_code()
            );
            Err(err)
        }
        Ok(_) => {
            println!("{}: unexpected success", label);
            Err(Error::from(ErrorKind::Generic))
        }
    }
}

fn invoke_has_aes_key(session: &mut Session) -> optee_teec::Result<()> {
    let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
    session.invoke_command(Command::HasAesKey as u32, &mut operation)
}

fn invoke_generate_aes_key(session: &mut Session) -> optee_teec::Result<()> {
    let mut operation = Operation::new(0, ParamNone, ParamNone, ParamNone, ParamNone);
    session.invoke_command(Command::GenerateAesKey as u32, &mut operation)
}

fn invoke_import_aes_key(session: &mut Session) -> optee_teec::Result<()> {
    let key = [0u8; AES_KEY_SIZE];
    let p0 = ParamTmpRef::new_input(&key);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
    session.invoke_command(Command::ImportAesKey as u32, &mut operation)
}

fn invoke_export_aes_key(session: &mut Session) -> optee_teec::Result<()> {
    let mut buffer = [0u8; AES_KEY_SIZE];
    let p0 = ParamTmpRef::new_output(&mut buffer);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
    session.invoke_command(Command::ExportAesKey as u32, &mut operation)
}

fn main() -> optee_teec::Result<()> {
    let mut context = Context::new()?;
    let uuid = parse_uuid()?;
    let mut session = context.open_session(uuid)?;

    expect_access_denied("has_aes_key", || invoke_has_aes_key(&mut session))?;
    expect_access_denied("generate_aes_key", || invoke_generate_aes_key(&mut session))?;
    expect_access_denied("import_aes_key", || invoke_import_aes_key(&mut session))?;
    expect_access_denied("export_aes_key", || invoke_export_aes_key(&mut session))?;

    println!("Policy checks completed.");
    Ok(())
}
