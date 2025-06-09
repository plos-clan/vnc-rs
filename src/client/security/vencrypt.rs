use crate::VncError;
use rustls::{ClientConfig, ServerName, Certificate, Error as TlsError};
use rustls::client::{ServerCertVerifier, ServerCertVerified};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{TlsConnector, client::TlsStream as ClientTlsStream};

/// A certificate verifier that accepts all certificates (for VNC self-signed certs)
struct AcceptAllVerifier;

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }
}
use tracing::{debug, info, trace};

/// VeNCrypt version - we support version 0.2
const VENCRYPT_VERSION: (u8, u8) = (0, 2);

/// VeNCrypt subtypes as defined in the security specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VeNCryptSubtype {
    Plain = 256,
    TlsNone = 257,
    TlsVnc = 258,
    TlsPlain = 259,
    X509None = 260,
    X509Vnc = 261,
    X509Plain = 262,
    TlsSasl = 263,
    X509Sasl = 264,
}

impl TryFrom<u32> for VeNCryptSubtype {
    type Error = VncError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            256 => Ok(VeNCryptSubtype::Plain),
            257 => Ok(VeNCryptSubtype::TlsNone),
            258 => Ok(VeNCryptSubtype::TlsVnc),
            259 => Ok(VeNCryptSubtype::TlsPlain),
            260 => Ok(VeNCryptSubtype::X509None),
            261 => Ok(VeNCryptSubtype::X509Vnc),
            262 => Ok(VeNCryptSubtype::X509Plain),
            263 => Ok(VeNCryptSubtype::TlsSasl),
            264 => Ok(VeNCryptSubtype::X509Sasl),
            _ => Err(VncError::General(format!("Unsupported VeNCrypt subtype: {}", value))),
        }
    }
}

impl From<VeNCryptSubtype> for u32 {
    fn from(subtype: VeNCryptSubtype) -> Self {
        subtype as u32
    }
}

impl VeNCryptSubtype {
    /// Check if this subtype requires TLS
    pub fn requires_tls(&self) -> bool {
        matches!(
            self,
            VeNCryptSubtype::TlsNone
                | VeNCryptSubtype::TlsVnc
                | VeNCryptSubtype::TlsPlain
                | VeNCryptSubtype::X509None
                | VeNCryptSubtype::X509Vnc
                | VeNCryptSubtype::X509Plain
                | VeNCryptSubtype::TlsSasl
                | VeNCryptSubtype::X509Sasl
        )
    }

    /// Check if this subtype requires plain username/password authentication
    pub fn requires_plain_auth(&self) -> bool {
        matches!(
            self,
            VeNCryptSubtype::Plain | VeNCryptSubtype::TlsPlain | VeNCryptSubtype::X509Plain
        )
    }
}

/// Wrapper for either a plain stream or TLS stream
pub enum VncStream<S> {
    Plain(S),
    Tls(ClientTlsStream<S>),
}

impl<S> AsyncRead for VncStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            VncStream::Plain(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            VncStream::Tls(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<S> AsyncWrite for VncStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            VncStream::Plain(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            VncStream::Tls(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            VncStream::Plain(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            VncStream::Tls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            VncStream::Plain(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            VncStream::Tls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}



/// VeNCrypt authentication handler
pub struct VeNCryptAuth;

impl VeNCryptAuth {
    /// Perform VeNCrypt version negotiation
    async fn negotiate_version<S>(stream: &mut S) -> Result<(), VncError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Read server's VeNCrypt version
        let server_major = stream.read_u8().await?;
        let server_minor = stream.read_u8().await?;
        
        debug!("Server VeNCrypt version: {}.{}", server_major, server_minor);

        // We only support version 0.2
        if server_major != 0 || server_minor < 2 {
            return Err(VncError::General(format!(
                "Unsupported VeNCrypt version {}.{}, we require 0.2+",
                server_major, server_minor
            )));
        }

        // Send our supported version (0.2)
        stream.write_u8(VENCRYPT_VERSION.0).await?;
        stream.write_u8(VENCRYPT_VERSION.1).await?;
        
        trace!("Sent VeNCrypt version: {}.{}", VENCRYPT_VERSION.0, VENCRYPT_VERSION.1);

        // Read server's response (should be 0 for OK)
        let response = stream.read_u8().await?;
        if response != 0 {
            return Err(VncError::General(
                "Server rejected VeNCrypt version negotiation".to_string(),
            ));
        }

        info!("VeNCrypt version negotiation successful");
        Ok(())
    }

    /// Negotiate VeNCrypt subtype
    async fn negotiate_subtype<S>(stream: &mut S) -> Result<VeNCryptSubtype, VncError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Read number of subtypes
        let num_subtypes = stream.read_u8().await?;
        debug!("Server supports {} VeNCrypt subtypes", num_subtypes);

        if num_subtypes == 0 {
            return Err(VncError::General("Server supports no VeNCrypt subtypes".to_string()));
        }

        // Read supported subtypes
        let mut supported_subtypes = Vec::new();
        for _ in 0..num_subtypes {
            let subtype_code = stream.read_u32().await?;
            if let Ok(subtype) = VeNCryptSubtype::try_from(subtype_code) {
                supported_subtypes.push(subtype);
                debug!("Server supports VeNCrypt subtype: {:?}", subtype);
            } else {
                debug!("Server supports unknown VeNCrypt subtype: {}", subtype_code);
            }
        }

        // Choose preferred subtype (prioritize X509Plain if available)
        let preferred_subtypes = [
            VeNCryptSubtype::X509Plain,
            VeNCryptSubtype::TlsPlain,
            VeNCryptSubtype::Plain,
            VeNCryptSubtype::X509None,
            VeNCryptSubtype::TlsNone,
        ];

        let selected_subtype = preferred_subtypes
            .iter()
            .find(|&&subtype| supported_subtypes.contains(&subtype))
            .copied()
            .ok_or_else(|| {
                VncError::General(format!(
                    "No compatible VeNCrypt subtype found. Server supports: {:?}",
                    supported_subtypes
                ))
            })?;

        info!("Selected VeNCrypt subtype: {:?}", selected_subtype);

        // Send selected subtype to server
        stream.write_u32(selected_subtype.into()).await?;

        // Read server's acknowledgment
        let ack = stream.read_u8().await?;
        if ack != 1 {
            return Err(VncError::General(
                "Server rejected VeNCrypt subtype selection".to_string(),
            ));
        }

        Ok(selected_subtype)
    }

    /// Setup TLS connection if required by the selected subtype
    async fn setup_tls<S>(stream: S, subtype: VeNCryptSubtype, server_name: &str) -> Result<VncStream<S>, VncError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if !subtype.requires_tls() {
            return Ok(VncStream::Plain(stream));
        }

        info!("Setting up TLS connection for VeNCrypt subtype: {:?}", subtype);

        // Configure TLS client with custom verifier for VNC self-signed certificates
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        
        // Parse server name for TLS
        let server_name = ServerName::try_from(server_name)
            .map_err(|e| VncError::General(format!("Invalid server name: {}", e)))?;

        info!("Starting TLS handshake");
        
        // Perform TLS handshake
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| VncError::General(format!("TLS handshake failed: {}", e)))?;

        info!("TLS handshake completed successfully");
        Ok(VncStream::Tls(tls_stream))
    }

    /// Perform Plain authentication (username + password)
    async fn authenticate_plain<S>(
        stream: &mut S,
        username: &str,
        password: &str,
    ) -> Result<(), VncError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        info!("Performing Plain authentication for user: {}", username);

        // Convert strings to bytes
        let username_bytes = username.as_bytes();
        let password_bytes = password.as_bytes();

        // Send username length and password length
        stream.write_u32(username_bytes.len() as u32).await?;
        stream.write_u32(password_bytes.len() as u32).await?;

        // Send username and password
        stream.write_all(username_bytes).await?;
        stream.write_all(password_bytes).await?;

        trace!("Sent Plain authentication credentials");
        Ok(())
    }

    /// Perform complete VeNCrypt authentication and return the stream (potentially wrapped in TLS)
    pub async fn authenticate<S>(
        mut stream: S,
        server_name: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<VncStream<S>, VncError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        info!("Starting VeNCrypt authentication");

        // Step 1: Version negotiation
        Self::negotiate_version(&mut stream).await?;

        // Step 2: Subtype negotiation
        let subtype = Self::negotiate_subtype(&mut stream).await?;

        // Step 3: TLS setup if required
        let mut stream = Self::setup_tls(stream, subtype, server_name).await?;

        // Step 4: Authentication based on subtype
        match subtype {
            VeNCryptSubtype::Plain | VeNCryptSubtype::TlsPlain | VeNCryptSubtype::X509Plain => {
                let username = username.ok_or_else(|| {
                    VncError::General("Username required for Plain authentication".to_string())
                })?;
                let password = password.ok_or_else(|| {
                    VncError::General("Password required for Plain authentication".to_string())
                })?;
                
                Self::authenticate_plain(&mut stream, username, password).await?;
            }
            VeNCryptSubtype::TlsNone | VeNCryptSubtype::X509None => {
                // No additional authentication required
                info!("No additional authentication required for {:?}", subtype);
            }
            _ => {
                return Err(VncError::General(format!(
                    "Authentication for subtype {:?} not implemented",
                    subtype
                )));
            }
        }

        info!("VeNCrypt authentication completed successfully");
        Ok(stream)
    }
}