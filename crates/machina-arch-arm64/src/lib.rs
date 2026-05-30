#![forbid(unsafe_code)]

pub mod abi;
pub mod decode;
pub mod pointer;
pub mod stubs;

pub use machina_arch::{ArchitectureKind, ArchitectureSpec, ByteOrder, GuestPointerWidth};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Arm64;

impl ArchitectureSpec for Arm64 {
    const KIND: ArchitectureKind = ArchitectureKind::Arm64;
    const NAME: &'static str = "arm64";
    const BYTE_ORDER: ByteOrder = ByteOrder::Little;
    const POINTER_WIDTH: GuestPointerWidth = GuestPointerWidth::Bits64;
    const INSTRUCTION_WIDTH: u8 = 4;
}

pub const ARCHITECTURE: Arm64 = Arm64;
