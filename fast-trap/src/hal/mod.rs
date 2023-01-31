#[cfg(not(doc))]
mod riscv;

#[cfg(not(doc))]
pub use riscv::*;

mod doc {
    #![allow(unused)]

    /// 设置全局陷入入口。
    ///
    /// # Safety
    ///
    /// 这个函数操作硬件寄存器，寄存器里原本的值将丢弃。
    pub unsafe fn load_direct_trap_entry() {}

    /// 把当前栈复用为陷入栈，预留 Handler 空间。
    ///
    /// # Safety
    ///
    /// 裸指针，直接移动 sp，只能在纯汇编环境调用。
    pub unsafe extern "C" fn reuse_stack_for_trap() {}

    /// 模拟一个 `cause` 类的陷入。
    ///
    /// # Safety
    ///
    /// 如同发生一个陷入。
    pub fn soft_trap(cause: usize) {}

    /// 陷入处理例程。
    ///
    /// # Safety
    ///
    /// 不要直接调用这个函数。暴露它仅仅是为了提供其入口的符号链接。
    pub unsafe extern "C" fn trap_entry() {}

    /// 陷入上下文。
    ///
    /// 保存了陷入时的寄存器状态。包括所有通用寄存器和 `pc`。
    pub struct FlowContext {}

    impl FlowContext {
        /// 零初始化。
        pub const ZERO: Self = Self {};
    }
}

#[cfg(doc)]
pub use doc::*;
