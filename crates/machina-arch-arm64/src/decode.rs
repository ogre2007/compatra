use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndirectBranchKind {
    Br,
    Blr,
}

impl IndirectBranchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Br => "br",
            Self::Blr => "blr",
        }
    }
}

impl fmt::Display for IndirectBranchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndirectBranch {
    pub kind: IndirectBranchKind,
    pub reg: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LdrUnsignedImmediate64 {
    pub rt: u8,
    pub rn: u8,
    pub offset: u64,
}

pub fn is_lse_cas(instr: u32) -> bool {
    let mask = (1u32 << 31)
        | (1u32 << 29)
        | (1u32 << 28)
        | (1u32 << 27)
        | (1u32 << 26)
        | (1u32 << 25)
        | (1u32 << 24)
        | (1u32 << 23)
        | (1u32 << 21)
        | (0x1Fu32 << 10);
    let value = (1u32 << 31) | (1u32 << 27) | (1u32 << 23) | (1u32 << 21) | (0x1Fu32 << 10);
    (instr & mask) == value
}

pub fn is_lse_ldadd(instr: u32) -> bool {
    (instr & 0x3F20_F000) == 0x3820_0000
}

pub fn is_lse_atomic_op(instr: u32) -> bool {
    (instr & 0x3F20_8C00) == 0x3820_0000
}

pub fn is_lse_swp(instr: u32) -> bool {
    (instr & 0x3F20_FC00) == 0x3820_8000
}

pub fn is_ldapr(instr: u32) -> bool {
    (instr & 0x3FFF_FC00) == 0x38BF_C000
}

pub fn decode_indirect_branch(instr: u32) -> Option<IndirectBranch> {
    let reg = ((instr >> 5) & 0x1F) as u8;
    match instr & 0xFFFF_FC1F {
        0xD61F_0000 => Some(IndirectBranch {
            kind: IndirectBranchKind::Br,
            reg,
        }),
        0xD63F_0000 => Some(IndirectBranch {
            kind: IndirectBranchKind::Blr,
            reg,
        }),
        _ => None,
    }
}

pub fn decode_ldr_uimm64(instr: u32) -> Option<LdrUnsignedImmediate64> {
    if (instr & 0xFFC0_0000) != 0xF940_0000 {
        return None;
    }
    let rt = (instr & 0x1F) as u8;
    let rn = ((instr >> 5) & 0x1F) as u8;
    let imm12 = ((instr >> 10) & 0xFFF) as u64;
    Some(LdrUnsignedImmediate64 {
        rt,
        rn,
        offset: imm12 << 3,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indirect_branch_decodes_register_and_kind() {
        assert_eq!(
            decode_indirect_branch(0xD61F_0200),
            Some(IndirectBranch {
                kind: IndirectBranchKind::Br,
                reg: 16,
            })
        );
        assert_eq!(
            decode_indirect_branch(0xD63F_0200),
            Some(IndirectBranch {
                kind: IndirectBranchKind::Blr,
                reg: 16,
            })
        );
    }

    #[test]
    fn ldr_unsigned_immediate64_decodes_scaled_offset() {
        let instr = 0xF940_0000 | (4 << 10) | (9 << 5) | 8;
        assert_eq!(
            decode_ldr_uimm64(instr),
            Some(LdrUnsignedImmediate64 {
                rt: 8,
                rn: 9,
                offset: 0x20,
            })
        );
    }

    #[test]
    fn lse_family_masks_match_representative_words() {
        assert!(is_lse_cas(0x88A0_7C00));
        assert!(is_lse_ldadd(0x3820_0000));
        assert!(is_lse_atomic_op(0x3820_0000));
        assert!(is_lse_swp(0x3820_8000));
        assert!(is_ldapr(0x38BF_C000));
    }
}
