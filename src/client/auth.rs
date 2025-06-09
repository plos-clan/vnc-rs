use crate::protocol::security::{des, types::AuthResult};
use crate::VncError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Credentials for VNC authentication
#[derive(Debug, Default, Clone)]
pub struct Credentials {
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Credentials {
    /// Create credentials with no authentication
    pub fn new(username: Option<String>, password: Option<String>) -> Self {
        Self { username, password }
    }

    /// Get password reference if available
    pub fn get_password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Get username reference if available
    pub fn get_username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Check if credentials have any authentication info
    pub fn is_none(&self) -> bool {
        self.username.is_none() && self.password.is_none()
    }
}

pub(super) struct AuthHelper {
    challenge: [u8; 16],
    key: [u8; 8],
}

impl AuthHelper {
    pub(super) async fn read<S>(reader: &mut S, password: &str) -> Result<Self, VncError>
    where
        S: AsyncRead + Unpin,
    {
        let mut challenge = [0; 16];
        reader.read_exact(&mut challenge).await?;

        let credential_len = password.len();
        let mut key = [0u8; 8];
        for (i, key_i) in key.iter_mut().enumerate() {
            let c = if i < credential_len {
                password.as_bytes()[i]
            } else {
                0
            };
            let mut cs = 0u8;
            for j in 0..8 {
                cs |= ((c >> j) & 1) << (7 - j)
            }
            *key_i = cs;
        }

        Ok(Self { challenge, key })
    }

    pub(super) async fn write<S>(&self, writer: &mut S) -> Result<(), VncError>
    where
        S: AsyncWrite + Unpin,
    {
        let encrypted = des::encrypt(&self.challenge, &self.key);
        writer.write_all(&encrypted).await?;
        Ok(())
    }

    pub(super) async fn finish<S>(self, reader: &mut S) -> Result<AuthResult, VncError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let result = reader.read_u32().await?;
        Ok(result.into())
    }
}
