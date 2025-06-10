use anyhow::{Context, Result};
use argh::FromArgs;
use minifb::{Key, MouseButton, MouseMode, Window, WindowOptions};
use std::collections::HashSet;
use tokio::{self, net::TcpStream};
use tracing::Level;
use vnc::{
    ClientKeyEvent, ClientMouseEvent, Credentials, PixelFormat, Rect, VncConnector, VncEncoding,
    VncEvent, X11Event,
};

#[derive(FromArgs)]
#[argh(description = "A simple VNC client written in Rust")]
struct Args {
    #[argh(option, short = 'h')]
    #[argh(default = "String::from(\"127.0.0.1:5900\")")]
    #[argh(description = "VNC server host and port")]
    host: String,

    #[argh(option, short = 'u')]
    #[argh(description = "username for authentication")]
    username: Option<String>,

    #[argh(option, short = 'p')]
    #[argh(description = "password for authentication")]
    password: Option<String>,
}

struct CanvasUtils {
    window: Window,
    buffer: Vec<u32>,
    width: u32,
    height: u32,
}

impl CanvasUtils {
    fn new() -> Result<Self> {
        Ok(Self {
            window: Window::new("vncviewer", 800_usize, 600_usize, WindowOptions::default())
                .with_context(|| "Unable to create window".to_string())?,
            buffer: vec![],
            width: 800,
            height: 600,
        })
    }

    fn init(&mut self, width: u32, height: u32) -> Result<()> {
        let mut window = Window::new(
            "vncviewer",
            width as usize,
            height as usize,
            WindowOptions::default(),
        )
        .with_context(|| "Unable to create window")?;
        window.set_target_fps(60);
        self.window = window;
        self.width = width;
        self.height = height;
        self.buffer.resize(height as usize * width as usize, 0);
        Ok(())
    }

    fn draw(&mut self, rect: Rect, data: Vec<u8>) -> Result<()> {
        // since we set the PixelFormat as bgra
        // the pixels must be sent in [blue, green, red, alpha] in the network order

        let mut s_idx = 0;
        for y in rect.y..rect.y + rect.height {
            let mut d_idx = y as usize * self.width as usize + rect.x as usize;

            for _ in rect.x..rect.x + rect.width {
                self.buffer[d_idx] =
                    u32::from_le_bytes(data[s_idx..s_idx + 4].try_into().unwrap()) & 0x00_ff_ff_ff;
                s_idx += 4;
                d_idx += 1;
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.window
            .update_with_buffer(&self.buffer, self.width as usize, self.height as usize)
            .with_context(|| "Unable to update screen buffer")?;
        Ok(())
    }

    fn copy(&mut self, dst: Rect, src: Rect) -> Result<()> {
        println!("Copy");
        let mut tmp = vec![0; src.width as usize * src.height as usize];
        let mut tmp_idx = 0;
        for y in 0..src.height as usize {
            let mut s_idx = (src.y as usize + y) * self.width as usize + src.x as usize;
            for _ in 0..src.width {
                tmp[tmp_idx] = self.buffer[s_idx];
                tmp_idx += 1;
                s_idx += 1;
            }
        }
        tmp_idx = 0;
        for y in 0..src.height as usize {
            let mut d_idx = (dst.y as usize + y) * self.width as usize + dst.x as usize;
            for _ in 0..src.width {
                self.buffer[d_idx] = tmp[tmp_idx];
                tmp_idx += 1;
                d_idx += 1;
            }
        }
        Ok(())
    }

    fn hande_vnc_event(&mut self, event: VncEvent) -> Result<()> {
        match event {
            VncEvent::SetResolution(screen) => {
                tracing::info!("Resize {:?}", screen);
                self.init(screen.width as u32, screen.height as u32)?
            }
            VncEvent::RawImage(rect, data) => {
                self.draw(rect, data)?;
            }
            VncEvent::Bell => {
                tracing::warn!("Bell event got, but ignore it");
            }
            VncEvent::SetPixelFormat(_) => unreachable!(),
            VncEvent::Copy(dst, src) => {
                self.copy(dst, src)?;
            }
            VncEvent::JpegImage(_rect, _data) => {
                tracing::warn!("Jpeg event got, but ignore it");
            }
            VncEvent::SetCursor(rect, data) => {
                if rect.width != 0 {
                    self.draw(rect, data)?;
                }
            }
            VncEvent::Text(string) => {
                tracing::info!("Got clipboard message {}", string);
            }
            _ => tracing::error!("{:?}", event),
        }
        Ok(())
    }
}

/// Map minifb Key to X11 keysym codes used by VNC protocol
fn minifb_key_to_x11_keysym(key: Key) -> Option<u32> {
    match key {
        // Numbers 0-9
        Key::Key0 => Some(0x030), // XK_0
        Key::Key1 => Some(0x031), // XK_1
        Key::Key2 => Some(0x032), // XK_2
        Key::Key3 => Some(0x033), // XK_3
        Key::Key4 => Some(0x034), // XK_4
        Key::Key5 => Some(0x035), // XK_5
        Key::Key6 => Some(0x036), // XK_6
        Key::Key7 => Some(0x037), // XK_7
        Key::Key8 => Some(0x038), // XK_8
        Key::Key9 => Some(0x039), // XK_9

        // Letters A-Z (lowercase)
        Key::A => Some(0x061), // XK_a
        Key::B => Some(0x062), // XK_b
        Key::C => Some(0x063), // XK_c
        Key::D => Some(0x064), // XK_d
        Key::E => Some(0x065), // XK_e
        Key::F => Some(0x066), // XK_f
        Key::G => Some(0x067), // XK_g
        Key::H => Some(0x068), // XK_h
        Key::I => Some(0x069), // XK_i
        Key::J => Some(0x06a), // XK_j
        Key::K => Some(0x06b), // XK_k
        Key::L => Some(0x06c), // XK_l
        Key::M => Some(0x06d), // XK_m
        Key::N => Some(0x06e), // XK_n
        Key::O => Some(0x06f), // XK_o
        Key::P => Some(0x070), // XK_p
        Key::Q => Some(0x071), // XK_q
        Key::R => Some(0x072), // XK_r
        Key::S => Some(0x073), // XK_s
        Key::T => Some(0x074), // XK_t
        Key::U => Some(0x075), // XK_u
        Key::V => Some(0x076), // XK_v
        Key::W => Some(0x077), // XK_w
        Key::X => Some(0x078), // XK_x
        Key::Y => Some(0x079), // XK_y
        Key::Z => Some(0x07a), // XK_z

        // Function keys F1-F15
        Key::F1 => Some(0xffbe),  // XK_F1
        Key::F2 => Some(0xffbf),  // XK_F2
        Key::F3 => Some(0xffc0),  // XK_F3
        Key::F4 => Some(0xffc1),  // XK_F4
        Key::F5 => Some(0xffc2),  // XK_F5
        Key::F6 => Some(0xffc3),  // XK_F6
        Key::F7 => Some(0xffc4),  // XK_F7
        Key::F8 => Some(0xffc5),  // XK_F8
        Key::F9 => Some(0xffc6),  // XK_F9
        Key::F10 => Some(0xffc7), // XK_F10
        Key::F11 => Some(0xffc8), // XK_F11
        Key::F12 => Some(0xffc9), // XK_F12
        Key::F13 => Some(0xffca), // XK_F13
        Key::F14 => Some(0xffcb), // XK_F14
        Key::F15 => Some(0xffcc), // XK_F15

        // Arrow keys
        Key::Down => Some(0xff54),  // XK_Down
        Key::Left => Some(0xff51),  // XK_Left
        Key::Right => Some(0xff53), // XK_Right
        Key::Up => Some(0xff52),    // XK_Up

        // Special characters
        Key::Apostrophe => Some(0x027),   // XK_apostrophe
        Key::Backquote => Some(0x060),    // XK_grave
        Key::Backslash => Some(0x05c),    // XK_backslash
        Key::Comma => Some(0x02c),        // XK_comma
        Key::Equal => Some(0x03d),        // XK_equal
        Key::LeftBracket => Some(0x05b),  // XK_bracketleft
        Key::Minus => Some(0x02d),        // XK_minus
        Key::Period => Some(0x02e),       // XK_period
        Key::RightBracket => Some(0x05d), // XK_bracketright
        Key::Semicolon => Some(0x03b),    // XK_semicolon
        Key::Slash => Some(0x02f),        // XK_slash

        // Control keys
        Key::Backspace => Some(0xff08), // XK_BackSpace
        Key::Delete => Some(0xffff),    // XK_Delete
        Key::End => Some(0xff57),       // XK_End
        Key::Enter => Some(0xff0d),     // XK_Return
        Key::Escape => Some(0xff1b),    // XK_Escape
        Key::Home => Some(0xff50),      // XK_Home
        Key::Insert => Some(0xff63),    // XK_Insert
        Key::Menu => Some(0xff67),      // XK_Menu
        Key::PageDown => Some(0xff56),  // XK_Next
        Key::PageUp => Some(0xff55),    // XK_Prior
        Key::Pause => Some(0xff13),     // XK_Pause
        Key::Space => Some(0x020),      // XK_space
        Key::Tab => Some(0xff09),       // XK_Tab

        // Lock keys
        Key::NumLock => Some(0xff7f),    // XK_Num_Lock
        Key::CapsLock => Some(0xffe5),   // XK_Caps_Lock
        Key::ScrollLock => Some(0xff14), // XK_Scroll_Lock

        // Modifier keys
        Key::LeftShift => Some(0xffe1),  // XK_Shift_L
        Key::RightShift => Some(0xffe2), // XK_Shift_R
        Key::LeftCtrl => Some(0xffe3),   // XK_Control_L
        Key::RightCtrl => Some(0xffe4),  // XK_Control_R
        Key::LeftSuper => Some(0xffeb),  // XK_Super_L
        Key::RightSuper => Some(0xffec), // XK_Super_R
        Key::LeftAlt => Some(0xffe9),    // XK_Alt_L
        Key::RightAlt => Some(0xffea),   // XK_Alt_R

        // Numeric keypad
        Key::NumPad0 => Some(0xffb0),        // XK_KP_0
        Key::NumPad1 => Some(0xffb1),        // XK_KP_1
        Key::NumPad2 => Some(0xffb2),        // XK_KP_2
        Key::NumPad3 => Some(0xffb3),        // XK_KP_3
        Key::NumPad4 => Some(0xffb4),        // XK_KP_4
        Key::NumPad5 => Some(0xffb5),        // XK_KP_5
        Key::NumPad6 => Some(0xffb6),        // XK_KP_6
        Key::NumPad7 => Some(0xffb7),        // XK_KP_7
        Key::NumPad8 => Some(0xffb8),        // XK_KP_8
        Key::NumPad9 => Some(0xffb9),        // XK_KP_9
        Key::NumPadDot => Some(0xffae),      // XK_KP_Decimal
        Key::NumPadSlash => Some(0xffaf),    // XK_KP_Divide
        Key::NumPadAsterisk => Some(0xffaa), // XK_KP_Multiply
        Key::NumPadMinus => Some(0xffad),    // XK_KP_Subtract
        Key::NumPadPlus => Some(0xffab),     // XK_KP_Add
        Key::NumPadEnter => Some(0xff8d),    // XK_KP_Enter

        // Unmapped keys
        Key::Unknown | Key::Count => None,
    }
}

/// Handle key state changes and send VNC key events
async fn handle_key_events(
    window: &Window,
    vnc: &vnc::VncClient,
    pressed_keys: &mut HashSet<Key>,
) -> Result<()> {
    // Get currently pressed keys
    let current_keys: HashSet<Key> = window.get_keys().into_iter().collect();

    // Find newly pressed keys
    for &key in &current_keys {
        if !pressed_keys.contains(&key) {
            if let Some(keysym) = minifb_key_to_x11_keysym(key) {
                let key_event = ClientKeyEvent {
                    keycode: keysym,
                    down: true,
                };
                let _ = vnc.input(X11Event::KeyEvent(key_event)).await;
            }
        }
    }

    // Find newly released keys
    for &key in pressed_keys.iter() {
        if !current_keys.contains(&key) {
            if let Some(keysym) = minifb_key_to_x11_keysym(key) {
                let key_event = ClientKeyEvent {
                    keycode: keysym,
                    down: false,
                };
                let _ = vnc.input(X11Event::KeyEvent(key_event)).await;
            }
        }
    }

    // Update pressed keys state
    *pressed_keys = current_keys;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Create tracing subscriber
    let level = if cfg!(debug_assertions) {
        Level::TRACE
    } else {
        Level::INFO
    };

    let subscriber = tracing_subscriber::fmt()
        .pretty()
        .with_max_level(level)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("failed to setting default subscriber");

    // Parse command line arguments manually
    let args: Args = argh::from_env();

    println!("Connecting to VNC server at {}", args.host);

    let tcp = TcpStream::connect(&args.host).await?;
    let vnc = VncConnector::new(tcp)
        .set_credentials(Credentials::new(args.username, args.password))
        .add_encoding(VncEncoding::Tight)
        .add_encoding(VncEncoding::Zrle)
        .add_encoding(VncEncoding::CopyRect)
        .add_encoding(VncEncoding::Raw)
        .allow_shared(true)
        .set_pixel_format(PixelFormat::bgra())
        .build()?
        .try_start()
        .await?
        .finish()?;

    let mut canvas = CanvasUtils::new()?;

    // Mouse state tracking
    let mut last_mouse_pos = (0.0, 0.0);
    let mut last_mouse_buttons = 0u8;

    // Keyboard state tracking
    let mut pressed_keys: HashSet<Key> = HashSet::new();

    let mut now = std::time::Instant::now();
    loop {
        match vnc.poll_event().await {
            Ok(Some(e)) => {
                let _ = canvas.hande_vnc_event(e);
            }
            Ok(None) => (),
            Err(e) => {
                tracing::error!("{}", e.to_string());
                break;
            }
        }

        // Handle keyboard input
        if canvas.window.is_open() {
            let _ = handle_key_events(&canvas.window, &vnc, &mut pressed_keys).await;
        }

        // Handle mouse input
        if canvas.window.is_open() {
            if let Some((x, y)) = canvas.window.get_mouse_pos(MouseMode::Clamp) {
                let mut buttons = 0u8;

                // Check mouse buttons - VNC button mask format:
                // bit 0: left button
                // bit 1: middle button
                // bit 2: right button
                if canvas.window.get_mouse_down(MouseButton::Left) {
                    buttons |= 1;
                }
                if canvas.window.get_mouse_down(MouseButton::Middle) {
                    buttons |= 2;
                }
                if canvas.window.get_mouse_down(MouseButton::Right) {
                    buttons |= 4;
                }

                // Send mouse event if position or buttons changed
                if (x, y) != last_mouse_pos || buttons != last_mouse_buttons {
                    let mouse_event = ClientMouseEvent {
                        position_x: x as u16,
                        position_y: y as u16,
                        bottons: buttons,
                    };
                    let _ = vnc.input(X11Event::PointerEvent(mouse_event)).await;
                    last_mouse_pos = (x, y);
                    last_mouse_buttons = buttons;
                }
            }

            // Handle scroll wheel
            if let Some((_scroll_x, scroll_y)) = canvas.window.get_scroll_wheel() {
                if scroll_y != 0.0 {
                    // VNC scroll wheel: button 4 for up, button 5 for down
                    let scroll_button = if scroll_y > 0.0 { 8 } else { 16 }; // bit 3 for up, bit 4 for down
                    let mouse_event = ClientMouseEvent {
                        position_x: last_mouse_pos.0 as u16,
                        position_y: last_mouse_pos.1 as u16,
                        bottons: scroll_button,
                    };
                    let _ = vnc.input(X11Event::PointerEvent(mouse_event)).await;

                    // Send button release immediately after
                    let mouse_event_release = ClientMouseEvent {
                        position_x: last_mouse_pos.0 as u16,
                        position_y: last_mouse_pos.1 as u16,
                        bottons: 0,
                    };
                    let _ = vnc.input(X11Event::PointerEvent(mouse_event_release)).await;
                }
            }
        }

        if now.elapsed().as_millis() > 16 {
            let _ = canvas.flush();
            let _ = vnc.input(X11Event::Refresh).await;
            now = std::time::Instant::now();
        }
    }

    let _ = vnc.close().await;
    Ok(())
}
