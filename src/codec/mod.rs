use std::mem::MaybeUninit;

mod cursor;
mod raw;
mod tight;
mod trle;
mod zlib;
mod zrle;

pub(crate) use cursor::Decoder as CursorDecoder;
pub(crate) use raw::Decoder as RawDecoder;
pub(crate) use tight::Decoder as TightDecoder;
pub(crate) use trle::Decoder as TrleDecoder;
pub(crate) use zrle::Decoder as ZrleDecoder;

fn uninit_vec(len: usize) -> Vec<u8> {
    let mut vec = Vec::with_capacity(len);
    vec.spare_capacity_mut().fill(MaybeUninit::new(0));
    unsafe { vec.set_len(vec.capacity()) };
    vec
}
