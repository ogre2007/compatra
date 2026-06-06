#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchitectureKind {
    Arm64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ByteOrder {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestPointerWidth {
    Bits32,
    Bits64,
}

pub trait ArchitectureSpec {
    const KIND: ArchitectureKind;
    const NAME: &'static str;
    const BYTE_ORDER: ByteOrder;
    const POINTER_WIDTH: GuestPointerWidth;
    const INSTRUCTION_WIDTH: u8;
}
