#![no_std]
#![no_main]
#![feature(naked_functions)]
#![deny(warnings)]

use core::{
    arch::{asm, naked_asm},
    mem::{MaybeUninit, forget},
    ptr::{NonNull, null},
    unreachable,
};
use dtb_walker::{Dtb, DtbObj, HeaderError, Str, WalkOperation};
use fast_trap::{
    FastContext, FastResult, FlowContext, FreeTrapStack, load_direct_trap_entry,
    reuse_stack_for_trap, soft_trap, trap_entry,
};
use rcore_console::log;
use riscv::register::*;
use sifive_test_device::SifiveTestDevice;
use uart_16550::MmioSerialPort;

#[unsafe(link_section = ".bss.uninit")]
static mut ROOT_STACK: Stack = Stack([0; 4096]);
static mut FREE_STACK: Stack = Stack([0; 4096]);
static mut ROOT_CONTEXT: FlowContext = FlowContext::ZERO;

#[naked]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
unsafe extern "C" fn _start() -> ! {
    unsafe {
        naked_asm!(
            "   la   sp, {stack} + {stack_size}
            call {move_stack}
            call {main}
            j    {trap}
        ",
            stack_size = const 4096,
            stack      =   sym ROOT_STACK,
            move_stack =   sym reuse_stack_for_trap,
            main       =   sym rust_main,
            trap       =   sym trap_entry,
        )
    }
}

#[naked]
unsafe extern "C" fn exception() -> ! {
    unsafe { naked_asm!("unimp") }
}

extern "C" fn rust_main(_hartid: usize, dtb: *const u8) {
    // 清零 bss 段
    unsafe extern "C" {
        static mut sbss: u64;
        static mut ebss: u64;
    }
    unsafe {
        let mut ptr = &raw mut sbss;
        let end = &raw mut ebss;
        while ptr < end {
            ptr.write_volatile(0);
            ptr = ptr.add(1);
        }
    }
    // 初始化打印
    unsafe {
        Dtb::from_raw_parts_filtered(dtb, |e| {
            matches!(
                e,
                HeaderError::Misaligned(4) | HeaderError::LastCompVersion(_)
            )
        })
    }
    .unwrap()
    .walk(|path, obj| match obj {
        DtbObj::SubNode { name } => {
            if path.is_root() && name == Str::from("soc") {
                WalkOperation::StepInto
            } else if path.level() == 1 {
                #[inline]
                unsafe fn parse_address(str: &[u8]) -> usize {
                    usize::from_str_radix(unsafe { core::str::from_utf8_unchecked(str) }, 16)
                        .unwrap()
                }

                if name.starts_with("test") {
                    unsafe { TEST = parse_address(&name.as_bytes()[5..]) as _ };
                } else if name.starts_with("uart") || name.starts_with("serial") {
                    unsafe {
                        let (_, addr) = name.as_str().unwrap().split_once('@').unwrap();
                        UART = MaybeUninit::new(MmioSerialPort::new(parse_address(addr.as_bytes())))
                    };
                }
                WalkOperation::StepOver
            } else {
                WalkOperation::StepOver
            }
        }
        DtbObj::Property(_) => WalkOperation::StepOver,
    });
    rcore_console::init_console(&Console);
    rcore_console::set_log_level(option_env!("LOG"));
    rcore_console::test_log();

    #[cfg(feature = "m-mode")]
    mscratch::write(0x5050);
    #[cfg(feature = "s-mode")]
    sscratch::write(0x5050);
    let context_ptr = unsafe { NonNull::new_unchecked(&raw mut ROOT_CONTEXT) };

    // 测试构造和释放
    let _ = FreeTrapStack::new(
        unsafe { ROOT_STACK.range() },
        |_| {},
        context_ptr,
        fast_handler,
    )
    .unwrap();
    #[cfg(feature = "m-mode")]
    assert_eq!(0x5050, mscratch::read());
    #[cfg(feature = "s-mode")]
    assert_eq!(0x5050, sscratch::read());

    // 测试加载和卸载
    let _ = FreeTrapStack::new(
        unsafe { ROOT_STACK.range() },
        |_| {},
        context_ptr,
        fast_handler,
    )
    .unwrap()
    .load();
    #[cfg(feature = "m-mode")]
    assert_eq!(0x5050, mscratch::read());
    #[cfg(feature = "s-mode")]
    assert_eq!(0x5050, sscratch::read());

    // 加载一个新的陷入栈
    let loaded = FreeTrapStack::new(
        unsafe { ROOT_STACK.range() },
        |_| {},
        context_ptr,
        fast_handler,
    )
    .unwrap()
    .load();

    {
        // 叠加一个陷入栈用于临时保护
        let _loaded = FreeTrapStack::new(
            unsafe { FREE_STACK.range() },
            |_| {},
            context_ptr,
            fast_handler,
        )
        .unwrap()
        .load();
        // 模拟陷入
        unsafe { soft_trap(cause::CALL) };
    }

    #[cfg(feature = "m-mode")]
    {
        assert_ne!(0x5050, mscratch::read());
        log::debug!("mscratch: {:#x}", mscratch::read());
        unsafe { asm!("csrw mcause, {}", in(reg) cause::BOOT) };
    }
    #[cfg(feature = "s-mode")]
    {
        assert_ne!(0x5050, sscratch::read());
        log::debug!("sscratch: {:#x}", sscratch::read());
        unsafe { asm!("csrw scause, {}", in(reg) cause::BOOT) };
    }

    // 忘了它，在汇编里触发陷入还要用
    forget(loaded);

    // 加载陷入入口
    unsafe { load_direct_trap_entry() };
}

mod cause {
    pub(super) const BOOT: usize = 24;
    pub(super) const CALL: usize = 25;
}

extern "C" fn fast_handler(
    mut ctx: FastContext,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
) -> FastResult {
    #[cfg(feature = "m-mode")]
    {
        use {mcause::Exception as E, mcause::Trap as T};
        let cause = mcause::read();
        log::debug!("fast trap: {:?}({})", cause.cause(), cause.bits());
        match cause.cause() {
            T::Exception(E::IllegalInstruction) => {
                log::info!("Test pass");
                unsafe { &*TEST }.pass()
            }
            T::Exception(E::Unknown) => {
                match cause.bits() {
                    cause::BOOT => mepc::write(exception as _),
                    cause::CALL => log::warn!("call fast-trap inline!"),
                    _ => unreachable!(),
                }
                unsafe { mstatus::set_mpp(mstatus::MPP::Machine) };
                ctx.regs().a = [ctx.a0(), a1, a2, a3, a4, a5, a6, a7];
                ctx.restore()
            }
            T::Exception(_) | T::Interrupt(_) => unreachable!(),
        }
    }
    #[cfg(feature = "s-mode")]
    {
        use {scause::Exception as E, scause::Trap as T};
        let cause = scause::read();
        log::debug!("fast trap: {:?}({})", cause.cause(), cause.bits());
        match cause.cause() {
            T::Exception(E::IllegalInstruction) => {
                log::info!("Test pass");
                unsafe { &*TEST }.pass()
            }
            T::Exception(E::Unknown) => {
                match cause.bits() {
                    cause::BOOT => mepc::write(exception as _),
                    cause::CALL => log::warn!("call fast-trap inline!"),
                    _ => unreachable!(),
                }
                unsafe { sstatus::set_spp(sstatus::SPP::Supervisor) };
                ctx.regs().a = [ctx.a0(), a1, a2, a3, a4, a5, a6, a7];
                ctx.restore()
            }
            T::Exception(_) | T::Interrupt(_) => unreachable!(),
        }
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    log::error!("{info}");
    unsafe { &*TEST }.fail(-1 as _)
}

#[repr(C, align(4096))]
struct Stack([u8; 4096]);

impl Stack {
    fn range(&self) -> core::ops::Range<usize> {
        let ans = self.0.as_ptr_range();
        ans.start as usize..ans.end as usize
    }
}

struct Console;
static mut UART: MaybeUninit<MmioSerialPort> = MaybeUninit::uninit();
static mut TEST: *const SifiveTestDevice = null();

impl rcore_console::Console for Console {
    #[inline]
    fn put_char(&self, c: u8) {
        unsafe { UART.assume_init_mut() }.send(c);
    }
}
