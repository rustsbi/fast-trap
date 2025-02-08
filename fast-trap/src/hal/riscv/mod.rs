#![allow(missing_docs)]

#[cfg(feature = "riscv-m")]
#[macro_use]
mod riscv_m;
#[cfg(feature = "riscv-s")]
#[macro_use]
mod riscv_s;

#[cfg(target_pointer_width = "32")]
#[macro_use]
mod arch {
    macro_rules! save {
        ($reg:ident => $ptr:ident[$pos:expr]) => {
            concat!(
                "sw ",
                stringify!($reg),
                ", 4*",
                $pos,
                '(',
                stringify!($ptr),
                ')'
            )
        };
    }

    macro_rules! load {
        ($ptr:ident[$pos:expr] => $reg:ident) => {
            concat!(
                "lw ",
                stringify!($reg),
                ", 4*",
                $pos,
                '(',
                stringify!($ptr),
                ')'
            )
        };
    }
}
#[cfg(target_pointer_width = "64")]
#[macro_use]
mod arch {
    macro_rules! save {
        ($reg:ident => $ptr:ident[$pos:expr]) => {
            concat!(
                "sd ",
                stringify!($reg),
                ", 8*",
                $pos,
                '(',
                stringify!($ptr),
                ')'
            )
        };
    }

    macro_rules! load {
        ($ptr:ident[$pos:expr] => $reg:ident) => {
            concat!(
                "ld ",
                stringify!($reg),
                ", 8*",
                $pos,
                '(',
                stringify!($ptr),
                ')'
            )
        };
    }
}

use crate::TrapHandler;
use core::alloc::Layout;

#[cfg(feature = "riscv-m")]
pub use riscv_m::*;
#[cfg(feature = "riscv-s")]
pub use riscv_s::*;

#[repr(C)]
#[allow(missing_docs)]
pub struct FlowContext {
    pub ra: usize,      // 0..
    pub t: [usize; 7],  // 1..
    pub a: [usize; 8],  // 8..
    pub s: [usize; 12], // 16..
    pub gp: usize,      // 28..
    pub tp: usize,      // 29..
    pub sp: usize,      // 30..
    pub pc: usize,      // 31..
}

impl FlowContext {
    /// 零初始化。
    pub const ZERO: Self = Self {
        ra: 0,
        t: [0; 7],
        a: [0; 8],
        s: [0; 12],
        gp: 0,
        tp: 0,
        sp: 0,
        pc: 0,
    };
}

/// # Safety
///
/// See [proto](crate::hal::doc::reuse_stack_for_trap).
#[naked]
pub unsafe extern "C" fn reuse_stack_for_trap() {
    const LAYOUT: Layout = Layout::new::<TrapHandler>();
    core::arch::naked_asm!(
        "   addi sp, sp, {size}
            andi sp, sp, {mask}
            ret
        ",
        size = const -(LAYOUT.size() as isize),
        mask = const !(LAYOUT.align() as isize - 1) ,
    )
}

/// # Safety
///
/// See [proto](crate::hal::doc::trap_entry).
#[naked]
pub unsafe extern "C" fn trap_entry() {
    core::arch::naked_asm!(
        ".align 2",
        // 换栈
        exchange!(),
        // 加载上下文指针
        save!(a0 => sp[2]),
        load!(sp[0] => a0),
        // 保存尽量少的寄存器
        save!(ra => a0[0]),
        save!(t0 => a0[1]),
        save!(t1 => a0[2]),
        save!(t2 => a0[3]),
        save!(t3 => a0[4]),
        save!(t4 => a0[5]),
        save!(t5 => a0[6]),
        save!(t6 => a0[7]),
        // 调用快速路径函数
        //
        // | reg    | position
        // | ------ | -
        // | ra     | `TrapHandler.context`
        // | t0-t6  | `TrapHandler.context`
        // | a0     | `TrapHandler.scratch`
        // | a1-a7  | 参数寄存器
        // | sp     | sscratch
        // | gp, tp | gp, tp
        // | s0-s11 | 不支持
        //
        // > 若要保留陷入上下文，
        // > 必须在快速路径保存 a0-a7 到 `TrapHandler.context`，
        // > 并进入完整路径执行后续操作。
        // >
        // > 若要切换上下文，在快速路径设置 gp/tp/sscratch/sepc 和 sstatus。
        "mv   a0, sp",
        load!(sp[1] => ra),
        "jalr ra",
        "0:", // 加载上下文指针
        load!(sp[0] => a1),
        // 0：设置少量参数寄存器
        "   beqz  a0, 0f",
        // 1：设置所有参数寄存器
        "   addi  a0, a0, -1
            beqz  a0, 1f
        ",
        // 2：设置所有调用者寄存器
        "   addi  a0, a0, -1
            beqz  a0, 2f
        ",
        // 3：设置所有寄存器
        "   addi  a0, a0, -1
            beqz  a0, 3f
        ",
        // 4：完整路径
        save!(s0  => a1[16]),
        save!(s1  => a1[17]),
        save!(s2  => a1[18]),
        save!(s3  => a1[19]),
        save!(s4  => a1[20]),
        save!(s5  => a1[21]),
        save!(s6  => a1[22]),
        save!(s7  => a1[23]),
        save!(s8  => a1[24]),
        save!(s9  => a1[25]),
        save!(s10 => a1[26]),
        save!(s11 => a1[27]),
        // 调用完整路径函数
        //
        // | reg    | position
        // | ------ | -
        // | sp     | sscratch
        // | gp, tp | gp, tp
        // | else   | `TrapHandler.context`
        //
        // > 若要保留陷入上下文，
        // > 在完整路径中保存 gp/tp/sp/pc 到 `TrapHandler.context`。
        // >
        // > 若要切换上下文，在完整路径设置 gp/tp/sscratch/sepc 和 sstatus。
        "mv   a0, sp",
        load!(sp[2] => ra),
        "jalr ra",
        "j    0b",
        "3:", // 设置所有寄存器
        load!(a1[16] => s0),
        load!(a1[17] => s1),
        load!(a1[18] => s2),
        load!(a1[19] => s3),
        load!(a1[20] => s4),
        load!(a1[21] => s5),
        load!(a1[22] => s6),
        load!(a1[23] => s7),
        load!(a1[24] => s8),
        load!(a1[25] => s9),
        load!(a1[26] => s10),
        load!(a1[27] => s11),
        "2:", // 设置所有调用者寄存器
        load!(a1[ 0] => ra),
        load!(a1[ 1] => t0),
        load!(a1[ 2] => t1),
        load!(a1[ 3] => t2),
        load!(a1[ 4] => t3),
        load!(a1[ 5] => t4),
        load!(a1[ 6] => t5),
        load!(a1[ 7] => t6),
        "1:", // 设置所有参数寄存器
        load!(a1[10] => a2),
        load!(a1[11] => a3),
        load!(a1[12] => a4),
        load!(a1[13] => a5),
        load!(a1[14] => a6),
        load!(a1[15] => a7),
        "0:", // 设置少量参数寄存器
        load!(a1[ 8] => a0),
        load!(a1[ 9] => a1),
        exchange!(),
        r#return!(),
    )
}
