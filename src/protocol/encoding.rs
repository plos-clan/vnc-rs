#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum VncEncoding {
    Raw = 0,
    CopyRect = 1,
    // Rre = 2,
    // Hextile = 5,
    Tight = 7,
    Trle = 15,
    Zrle = 16,
    CursorPseudo = -239,
    DesktopSizePseudo = -223,
    LastRectPseudo = -224,
}

impl From<u32> for VncEncoding {
    fn from(num: u32) -> Self {
        match num {
            0 => VncEncoding::Raw,
            1 => VncEncoding::CopyRect,
            // 2 => VncEncoding::Rre,
            // 5 => VncEncoding::Hextile,
            7 => VncEncoding::Tight,
            15 => VncEncoding::Trle,
            16 => VncEncoding::Zrle,
            val if val == -239i32 as u32 => VncEncoding::CursorPseudo,
            val if val == -223i32 as u32 => VncEncoding::DesktopSizePseudo,
            val if val == -224i32 as u32 => VncEncoding::LastRectPseudo,
            _ => panic!("Unknown encoding: {num}"),
        }
    }
}

impl From<VncEncoding> for u32 {
    fn from(e: VncEncoding) -> Self {
        e as u32
    }
}
