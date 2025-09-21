use optee_teec::{Context, ErrorKind, Operation, ParamNone, ParamTmpRef, Session, Uuid};

pub struct KeyProvisionTaConnector {
    sess: Session,
}

impl KeyProvisionTaConnector {
    pub fn new(ctx: &mut Context) -> optee_teec::Result<Self> {
        let uuid = Uuid::parse_str(inference::UUID).map_err(|err| {
            println!(
                "parse uuid \"{}\" failed due to: {:?}",
                inference::UUID,
                err
            );
            ErrorKind::BadParameters
        })?;

        let dummy_data = vec![0u8; 16];
        let mut open_op = Operation::new(
            0,
            ParamTmpRef::new_input(&dummy_data),
            ParamNone,
            ParamNone,
            ParamNone,
        );

        let sess = ctx.open_session_with_operation(uuid, &mut open_op)?;
        Ok(Self { sess })
    }

    pub fn store_key(&mut self, key: &[u8; 32]) -> optee_teec::Result<()> {
        let mut op = Operation::new(
            3,
            ParamTmpRef::new_input(key),
            ParamNone,
            ParamNone,
            ParamNone,
        );
        self.sess.invoke_command(3, &mut op)?;
        Ok(())
    }
}

mod inference {
    pub const UUID: &str = include_str!("../../../enc_mnist-rs/ta/inference/uuid.txt");
}
