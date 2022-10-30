﻿mod riscv;
#[cfg(target_arch = "riscv32")]
mod riscv32_trap;
#[cfg(target_arch = "riscv64")]
mod riscv64_trap;
#[cfg(feature = "riscv_m")]
#[macro_use]
mod riscv_m;
#[cfg(feature = "riscv_s")]
#[macro_use]
mod riscv_s;

pub use riscv::*;
#[cfg(target_arch = "riscv32")]
pub use riscv32_trap::*;
#[cfg(target_arch = "riscv64")]
pub use riscv64_trap::*;
#[cfg(feature = "riscv_m")]
pub use riscv_m::*;
#[cfg(feature = "riscv_s")]
pub use riscv_s::*;
