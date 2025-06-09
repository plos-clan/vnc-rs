use crate::{VncError, VncVersion};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityType {
    Invalid = 0,
    None = 1,
    VncAuth = 2,
    RA2 = 5,
    RA2ne = 6,
    Tight = 16,
    Ultra = 17,
    Tls = 18,
    VeNCrypt = 19,
    GtkVncSasl = 20,
    Md5Hash = 21,
    ColinDeanXvp = 22,
    RA2_256 = 129,
}

impl TryFrom<u8> for SecurityType {
    type Error = VncError;
    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(SecurityType::Invalid),
            1 => Ok(SecurityType::None),
            2 => Ok(SecurityType::VncAuth),
            5 => Ok(SecurityType::RA2),
            6 => Ok(SecurityType::RA2ne),
            16 => Ok(SecurityType::Tight),
            17 => Ok(SecurityType::Ultra),
            18 => Ok(SecurityType::Tls),
            19 => Ok(SecurityType::VeNCrypt),
            20 => Ok(SecurityType::GtkVncSasl),
            21 => Ok(SecurityType::Md5Hash),
            22 => Ok(SecurityType::ColinDeanXvp),
            129 => Ok(SecurityType::RA2_256),
            invalid => Err(VncError::InvalidSecurityType(invalid)),
        }
    }
}

impl From<SecurityType> for u8 {
    fn from(e: SecurityType) -> Self {
        e as u8
    }
}

impl SecurityType {
    pub async fn read<S>(reader: &mut S, version: &VncVersion) -> Result<Vec<Self>, VncError>
    where
        S: AsyncRead + Unpin,
    {
        match version {
            VncVersion::RFB33 => {
                let security_type = reader.read_u32().await?;
                let security_type = (security_type as u8).try_into()?;
                if let SecurityType::Invalid = security_type {
                    let _ = reader.read_u32().await?;
                    let mut err_msg = String::new();
                    reader.read_to_string(&mut err_msg).await?;
                    return Err(VncError::General(err_msg));
                }
                Ok(vec![security_type])
            }
            _ => {
                // +--------------------------+-------------+--------------------------+
                // | No. of bytes             | Type        | Description              |
                // |                          | [Value]     |                          |
                // +--------------------------+-------------+--------------------------+
                // | 1                        | U8          | number-of-security-types |
                // | number-of-security-types | U8 array    | security-types           |
                // +--------------------------+-------------+--------------------------+
                let num = reader.read_u8().await?;

                if num == 0 {
                    let _ = reader.read_u32().await?;
                    let mut err_msg = String::new();
                    reader.read_to_string(&mut err_msg).await?;
                    return Err(VncError::General(err_msg));
                }
                let mut sec_types = vec![];
                for _ in 0..num {
                    sec_types.push(reader.read_u8().await?.try_into()?);
                }
                tracing::trace!("Server supported security type: {:?}", sec_types);
                Ok(sec_types)
            }
        }
    }

    pub async fn write<S>(&self, writer: &mut S) -> Result<(), VncError>
    where
        S: AsyncWrite + Unpin,
    {
        writer.write_all(&[(*self).into()]).await?;
        Ok(())
    }
}

#[allow(dead_code)]
#[repr(u32)]
pub enum AuthResult {
    Ok = 0,
    Failed = 1,
}

impl From<u32> for AuthResult {
    fn from(num: u32) -> Self {
        match num {
            0 => AuthResult::Ok,
            1 => AuthResult::Failed,
            _ => panic!("Invalid AuthResult value: {num}"),
        }
    }
}

impl From<AuthResult> for u32 {
    fn from(e: AuthResult) -> Self {
        e as u32
    }
}
