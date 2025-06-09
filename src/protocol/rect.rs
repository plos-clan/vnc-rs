/// A rect where the image should be updated
#[derive(Debug, Clone, Copy)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

/// Resolution format to resize window
#[derive(Debug, Clone)]
pub struct Screen {
    pub width: u16,
    pub height: u16,
}

impl From<(u16, u16)> for Screen {
    fn from(tuple: (u16, u16)) -> Self {
        Self {
            width: tuple.0,
            height: tuple.1,
        }
    }
}
