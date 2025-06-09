//! # VNC-RS
//!
//! ## Description
//! + An async implementation of VNC client side protocol
//!
//! ## Simple example
//!
//! ```no_run
//! use tokio::net::TcpStream;
//! use vnc::{Credentials, PixelFormat, VncConnector, VncEvent, VncEncoding};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to VNC server
//!     let tcp = TcpStream::connect("127.0.0.1:5900").await?;
//!
//!     // Create VNC connection with password authentication
//!     let vnc = VncConnector::new(tcp)
//!         .set_credentials(Credentials::new(None, Some("password".to_string())))
//!         .add_encoding(VncEncoding::Tight)
//!         .add_encoding(VncEncoding::Raw)
//!         .allow_shared(true)
//!         .set_pixel_format(PixelFormat::bgra())
//!         .build()?
//!         .try_start()
//!         .await?
//!         .finish()?;
//!
//!     // Handle VNC events
//!     loop {
//!         match vnc.poll_event().await {
//!             Ok(Some(event)) => {
//!                 match event {
//!                     VncEvent::SetResolution(screen) => {
//!                         println!("Screen resolution: {}x{}", screen.width, screen.height);
//!                     }
//!                     VncEvent::RawImage(rect, data) => {
//!                         println!("Received image data for rect: {:?}", rect);
//!                         // Process image data here
//!                     }
//!                     VncEvent::Bell => {
//!                         println!("Bell!");
//!                     }
//!                     _ => {}
//!                 }
//!             }
//!             Ok(None) => {
//!                 // No events
//!             }
//!             Err(e) => {
//!                 eprintln!("VNC error: {}", e);
//!                 break;
//!             }
//!         }
//!     }
//!
//!     vnc.close().await?;
//!     Ok(())
//! }
//! ```
//!
//! ## License
//!
//! Licensed under either of
//!
//!  * Apache License, Version 2.0
//!    ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
//!  * MIT license
//!    ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)
//!
//! at your option.
//!
//! ## Contribution
//!
//! Unless you explicitly state otherwise, any contribution intentionally submitted
//! for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
//! dual licensed as above, without any additional terms or conditions.

pub mod client;
pub mod codec;
pub mod error;
pub mod events;
pub mod protocol;

// 重新导出常用类型，方便调用方使用
pub use client::{Credentials, VncClient, VncConnector};
pub use error::*;
pub use events::*;
pub use protocol::{PixelFormat, Rect, Screen, VncEncoding, VncVersion};
