use crate::client::auth::AuthHelper;
use crate::protocol::security::vencrypt::{VeNCryptAuth, VncStream};
use crate::protocol::security::{AuthResult, SecurityType};
use crate::{Credentials, VncClient};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tracing::{info, trace};

use crate::{PixelFormat, VncEncoding, VncError, VncVersion};

pub enum VncState<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    Handshake(VncConnector<S>),
    Authenticate(VncConnector<S>),
    Connected(VncClient),
}

impl<S> VncState<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    pub async fn try_start(mut self) -> Result<Self, VncError> {
        loop {
            self = match self {
                VncState::Connected(_) => return Ok(self),
                VncState::Handshake(mut connector) => {
                    // Read the rfbversion informed by the server
                    let rfbversion = match &mut connector.stream {
                        VncStream::Plain(stream) => VncVersion::read(stream).await?,
                        VncStream::Tls(stream) => VncVersion::read(stream).await?,
                    };
                    trace!(
                        "Our version {:?}, server version {:?}",
                        connector.rfb_version,
                        rfbversion
                    );

                    // Record the negotiated rfbversion
                    connector.rfb_version = connector.rfb_version.min(rfbversion);
                    trace!("Negotiated rfb version: {:?}", connector.rfb_version);

                    match &mut connector.stream {
                        VncStream::Plain(stream) => rfbversion.write(stream).await?,
                        VncStream::Tls(stream) => rfbversion.write(stream).await?,
                    };
                    VncState::Authenticate(connector)
                }
                VncState::Authenticate(mut connector) => {
                    let security_types = match &mut connector.stream {
                        VncStream::Plain(stream) => {
                            SecurityType::read(stream, &connector.rfb_version).await?
                        }
                        VncStream::Tls(stream) => {
                            SecurityType::read(stream, &connector.rfb_version).await?
                        }
                    };

                    assert!(!security_types.is_empty());

                    if security_types.contains(&SecurityType::None) {
                        match connector.rfb_version {
                            VncVersion::RFB33 => {
                                info!("No auth needed in vnc3.3");
                            }
                            VncVersion::RFB37 => {
                                info!("No auth needed in vnc3.7");
                                match &mut connector.stream {
                                    VncStream::Plain(stream) => {
                                        SecurityType::write(&SecurityType::None, stream).await?
                                    }
                                    VncStream::Tls(stream) => {
                                        SecurityType::write(&SecurityType::None, stream).await?
                                    }
                                };
                            }
                            VncVersion::RFB38 => {
                                info!("No auth needed in vnc3.8");
                                match &mut connector.stream {
                                    VncStream::Plain(stream) => {
                                        SecurityType::write(&SecurityType::None, stream).await?;
                                        let mut ok = [0; 4];
                                        stream.read_exact(&mut ok).await?;
                                    }
                                    VncStream::Tls(stream) => {
                                        SecurityType::write(&SecurityType::None, stream).await?;
                                        let mut ok = [0; 4];
                                        stream.read_exact(&mut ok).await?;
                                    }
                                }
                            }
                        }
                    } else {
                        // choose a auth method
                        if security_types.contains(&SecurityType::VeNCrypt) {
                            // Handle VeNCrypt authentication (preferred)
                            if connector.rfb_version != VncVersion::RFB33 {
                                match &mut connector.stream {
                                    VncStream::Plain(stream) => {
                                        SecurityType::write(&SecurityType::VeNCrypt, stream).await?
                                    }
                                    VncStream::Tls(stream) => {
                                        SecurityType::write(&SecurityType::VeNCrypt, stream).await?
                                    }
                                };
                            }

                            let Some(password) = connector.credentials.password else {
                                return Err(VncError::MisingPassword);
                            };

                            let username = connector
                                .credentials
                                .username
                                .unwrap_or(String::default())
                                .to_string();

                            // Perform VeNCrypt authentication
                            let stream = connector.stream;
                            let plain_stream = match stream {
                                VncStream::Plain(s) => s,
                                VncStream::Tls(_) => {
                                    return Err(VncError::General(
                                        "Unexpected TLS stream".to_string(),
                                    ))
                                }
                            };
                            connector.stream = VeNCryptAuth::authenticate(
                                plain_stream,
                                "localhost",
                                Some(username.as_ref()),
                                Some(&password),
                            )
                            .await?;

                            // Read SecurityResult after VeNCrypt auth
                            let result = match &mut connector.stream {
                                VncStream::Plain(stream) => stream.read_u32().await?,
                                VncStream::Tls(stream) => stream.read_u32().await?,
                            };
                            let auth_result: AuthResult = result.into();
                            if let AuthResult::Failed = auth_result {
                                match &mut connector.stream {
                                    VncStream::Plain(stream) => {
                                        let _ = stream.read_u32().await?;
                                        let mut err_msg = String::new();
                                        stream.read_to_string(&mut err_msg).await?;
                                        return Err(VncError::General(err_msg));
                                    }
                                    VncStream::Tls(stream) => {
                                        let _ = stream.read_u32().await?;
                                        let mut err_msg = String::new();
                                        stream.read_to_string(&mut err_msg).await?;
                                        return Err(VncError::General(err_msg));
                                    }
                                };
                            }
                        } else if security_types.contains(&SecurityType::VncAuth) {
                            if connector.rfb_version != VncVersion::RFB33 {
                                match &mut connector.stream {
                                    VncStream::Plain(stream) => {
                                        SecurityType::write(&SecurityType::VncAuth, stream).await?
                                    }
                                    VncStream::Tls(stream) => {
                                        SecurityType::write(&SecurityType::VncAuth, stream).await?
                                    }
                                };
                            }

                            let Some(password) = &connector.credentials.password else {
                                return Err(VncError::MisingPassword);
                            };

                            // auth
                            match &mut connector.stream {
                                VncStream::Plain(stream) => {
                                    let auth = AuthHelper::read(stream, password).await?;
                                    auth.write(stream).await?;
                                    let result = auth.finish(stream).await?;
                                    if let AuthResult::Failed = result {
                                        if let VncVersion::RFB37 = connector.rfb_version {
                                            return Err(VncError::WrongPassword);
                                        } else {
                                            let _ = stream.read_u32().await?;
                                            let mut err_msg = String::new();
                                            stream.read_to_string(&mut err_msg).await?;
                                            return Err(VncError::General(err_msg));
                                        }
                                    }
                                }
                                VncStream::Tls(stream) => {
                                    let auth = AuthHelper::read(stream, password).await?;
                                    auth.write(stream).await?;
                                    let result = auth.finish(stream).await?;
                                    if let AuthResult::Failed = result {
                                        if let VncVersion::RFB37 = connector.rfb_version {
                                            return Err(VncError::WrongPassword);
                                        } else {
                                            let _ = stream.read_u32().await?;
                                            let mut err_msg = String::new();
                                            stream.read_to_string(&mut err_msg).await?;
                                            return Err(VncError::General(err_msg));
                                        }
                                    }
                                }
                            };
                        } else {
                            return Err(VncError::General(format!(
                                "Security types {:?} not supported",
                                security_types
                            )));
                        }
                    }
                    info!("Auth done, client connected");

                    return Ok(VncState::Connected(
                        VncClient::new(
                            connector.stream,
                            connector.allow_shared,
                            connector.pixel_format,
                            connector.encodings,
                        )
                        .await?,
                    ));
                }
            };
        }
    }

    pub fn finish(self) -> Result<VncClient, VncError> {
        match self {
            VncState::Connected(client) => Ok(client),
            _ => Err(VncError::ConnectError),
        }
    }
}

/// Connection Builder to setup a vnc client
pub struct VncConnector<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    stream: VncStream<S>,
    credentials: crate::client::auth::Credentials,
    rfb_version: VncVersion,
    allow_shared: bool,
    pixel_format: Option<PixelFormat>,
    encodings: Vec<VncEncoding>,
}

impl<S> VncConnector<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    /// To new a vnc client configuration with stream `S`
    ///
    /// `S` should implement async I/O methods
    ///
    /// ```no_run
    /// use vnc::{PixelFormat, VncConnector, VncError};
    /// use tokio::{self, net::TcpStream};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), VncError> {
    ///     let tcp = TcpStream::connect("127.0.0.1:5900").await?;
    ///     let vnc = VncConnector::new(tcp)
    ///         .set_credentials(vnc::Credentials::new(None, Some("password".to_string())))
    ///         .add_encoding(vnc::VncEncoding::Tight)
    ///         .add_encoding(vnc::VncEncoding::Zrle)
    ///         .add_encoding(vnc::VncEncoding::CopyRect)
    ///         .add_encoding(vnc::VncEncoding::Raw)
    ///         .allow_shared(true)
    ///         .set_pixel_format(PixelFormat::bgra())
    ///         .build()?
    ///         .try_start()
    ///         .await?
    ///         .finish()?;
    ///     Ok(())
    /// }
    /// ```
    ///
    pub fn new(stream: S) -> Self {
        Self {
            stream: VncStream::Plain(stream),
            credentials: Credentials::default(),
            allow_shared: true,
            rfb_version: VncVersion::RFB38,
            pixel_format: None,
            encodings: Vec::new(),
        }
    }

    /// Set credentials for VNC authentication
    pub fn set_credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = credentials;
        self
    }

    /// The max vnc version that we supported
    ///
    /// Version should be one of the [VncVersion]
    ///
    pub fn set_version(mut self, version: VncVersion) -> Self {
        self.rfb_version = version;
        self
    }

    /// Set the rgb order which you will use to resolve the image data
    ///
    /// In most of the case, use `PixelFormat::bgra()` on little endian PCs
    ///
    /// And use `PixelFormat::rgba()` on wasm apps (with canvas)
    ///
    /// Also, customized format is allowed
    ///
    /// Will use the default format informed by the vnc server if not set
    ///
    /// In this condition, the client will get a [crate::VncEvent::SetPixelFormat] event notified
    ///
    pub fn set_pixel_format(mut self, pf: PixelFormat) -> Self {
        self.pixel_format = Some(pf);
        self
    }

    /// Shared-flag is non-zero (true) if the server should try to share the
    ///
    /// desktop by leaving other clients connected, and zero (false) if it
    ///
    /// should give exclusive access to this client by disconnecting all
    ///
    /// other clients.
    ///
    pub fn allow_shared(mut self, allow_shared: bool) -> Self {
        self.allow_shared = allow_shared;
        self
    }

    /// Client encodings that we want to use
    ///
    /// One of [VncEncoding]
    ///
    /// [VncEncoding::Raw] must be sent as the RFC required
    ///
    /// The order to add encodings is the order to inform the server
    ///
    pub fn add_encoding(mut self, encoding: VncEncoding) -> Self {
        self.encodings.push(encoding);
        self
    }

    /// Complete the client configuration
    ///
    pub fn build(self) -> Result<VncState<S>, VncError> {
        if self.encodings.is_empty() {
            return Err(VncError::NoEncoding);
        }
        Ok(VncState::Handshake(self))
    }
}
