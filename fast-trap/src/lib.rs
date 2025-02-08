//! 快速陷入处理。

#![no_std]
#![feature(naked_functions)]
#![deny(warnings, missing_docs)]

mod entire;
mod fast;
mod hal;

pub use entire::*;
pub use fast::*;
pub use hal::{FlowContext, load_direct_trap_entry, reuse_stack_for_trap, soft_trap, trap_entry};

use core::{
    alloc::Layout,
    marker::PhantomPinned,
    mem::{MaybeUninit, align_of, forget},
    ops::Range,
    ptr::NonNull,
};

/// 游离的陷入栈。
pub struct FreeTrapStack(NonNull<TrapHandler>);

/// 已加载的陷入栈。
pub struct LoadedTrapStack(usize);

/// 构造陷入栈失败。
#[derive(Debug)]
pub struct IllegalStack;

impl FreeTrapStack {
    /// 在内存块上构造游离的陷入栈。
    pub fn new(
        range: Range<usize>,
        drop: fn(Range<usize>),

        context_ptr: NonNull<FlowContext>,
        fast_handler: FastHandler,
    ) -> Result<Self, IllegalStack> {
        const LAYOUT: Layout = Layout::new::<TrapHandler>();
        let bottom = range.start;
        let top = range.end;
        let ptr = (top - LAYOUT.size()) & !(LAYOUT.align() - 1);
        if ptr >= bottom {
            let handler = unsafe { &mut *(ptr as *mut TrapHandler) };
            handler.range = range;
            handler.drop = drop;
            handler.context = context_ptr;
            handler.fast_handler = fast_handler;
            Ok(Self(unsafe { NonNull::new_unchecked(handler) }))
        } else {
            Err(IllegalStack)
        }
    }

    /// 将这个陷入栈加载为预备陷入栈。
    #[inline]
    pub fn load(self) -> LoadedTrapStack {
        let scratch = hal::exchange_scratch(self.0.as_ptr() as _);
        forget(self);
        LoadedTrapStack(scratch)
    }
}

impl Drop for FreeTrapStack {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            let handler = self.0.as_ref();
            (handler.drop)(handler.range.clone());
        }
    }
}

impl LoadedTrapStack {
    /// 获取从 `sscratch` 寄存器中换出的值。
    #[inline]
    pub const fn val(&self) -> usize {
        self.0
    }

    /// 卸载陷入栈。
    #[inline]
    pub fn unload(self) -> FreeTrapStack {
        let ans = unsafe { self.unload_unchecked() };
        forget(self);
        ans
    }

    /// 卸载但不消费所有权。
    ///
    /// # Safety
    ///
    /// 间接复制了所有权。用于 `Drop`。
    #[inline]
    unsafe fn unload_unchecked(&self) -> FreeTrapStack {
        let ptr = hal::exchange_scratch(self.0) as *mut TrapHandler;
        let handler = unsafe { NonNull::new_unchecked(ptr) };
        FreeTrapStack(handler)
    }
}

impl Drop for LoadedTrapStack {
    #[inline]
    fn drop(&mut self) {
        drop(unsafe { self.unload_unchecked() })
    }
}

/// 陷入处理器上下文。
#[repr(C)]
struct TrapHandler {
    /// 指向一个陷入上下文的指针。
    ///
    /// # TODO
    ///
    /// 这个东西是怎么来的？生命周期是什么？
    /// 似乎让它生命周期和陷入栈绑定也很合理。
    /// 它可以交换，只是和陷入栈同时释放而已。
    ///
    /// - 发生陷入时，将寄存器保存到此对象。
    /// - 离开陷入处理时，按此对象的内容设置寄存器。
    context: NonNull<FlowContext>,
    /// 快速路径函数。
    ///
    /// 必须在初始化陷入时设置好。
    fast_handler: FastHandler,
    /// 可在汇编使用的临时存储。
    ///
    /// - 在快速路径开始时暂存 a0。
    /// - 在快速路径结束时保存完整路径函数。
    scratch: usize,

    range: Range<usize>,
    drop: fn(Range<usize>),

    /// 禁止移动标记。
    ///
    /// `TrapHandler` 是放在其内部定义的 `block` 块里的，这是一种自引用结构，不能移动。
    pinned: PhantomPinned,
}

impl TrapHandler {
    /// 如果从快速路径向完整路径转移，可以把一个对象放在栈底。
    /// 用这个方法找到栈底的一个对齐的位置。
    #[inline]
    fn locate_fast_mail<T>(&mut self) -> *mut MaybeUninit<T> {
        let top = self.range.end as *mut u8;
        let offset = top.align_offset(align_of::<T>());
        unsafe { &mut *top.add(offset).cast() }
    }
}
