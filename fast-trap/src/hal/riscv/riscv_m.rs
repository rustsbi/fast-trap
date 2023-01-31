use super::{trap_entry, FlowContext};
use core::arch::asm;

macro_rules! exchange {
    () => {
        exchange!(sp)
    };

    ($reg:ident) => {
        concat!("csrrw ", stringify!($reg), ", mscratch, ", stringify!($reg))
    };
}

macro_rules! r#return {
    () => {
        "mret"
    };
}

pub(super) use {exchange, r#return};

impl FlowContext {
    /// 从上下文向硬件加载非调用规范约定的寄存器。
    #[inline]
    pub(crate) unsafe fn load_others(&self) {
        asm!(
            "   mv         gp, {gp}
                mv         tp, {tp}
                csrw mscratch, {sp}
                csrw     mepc, {pc}
            ",
            gp = in(reg) self.gp,
            tp = in(reg) self.tp,
            sp = in(reg) self.sp,
            pc = in(reg) self.pc,
        );
    }
}

/// 交换突发寄存器。
#[inline]
pub(crate) fn exchange_scratch(mut val: usize) -> usize {
    unsafe { asm!("csrrw {0}, mscratch, {0}", inlateout(reg) val) };
    val
}

/// # Safety
///
/// See [proto](crate::hal::doc::soft_trap).
#[inline]
pub unsafe fn soft_trap(cause: usize) {
    asm!(
        "   la   {0},    1f
            csrw mepc,   {0}
            csrw mcause, {cause}
            j    {trap}
         1:
        ",
        out(reg) _,
        cause = in(reg) cause,
        trap  = sym trap_entry,
    );
}

/// # Safety
///
/// See [proto](crate::hal::doc::load_direct_trap_entry).
#[inline]
pub unsafe fn load_direct_trap_entry() {
    asm!("csrw mtvec, {0}", in(reg) trap_entry, options(nomem))
}
