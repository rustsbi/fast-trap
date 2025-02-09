use crate::{FlowContext, TrapHandler};
use core::{
    marker::PhantomData,
    mem::{MaybeUninit, forget},
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

/// 完整路径函数。
pub type EntireHandler<T> = extern "C" fn(EntireContext<T>) -> EntireResult;

/// 完整路径上下文。
#[repr(transparent)]
pub struct EntireContext<T: 'static = ()>(NonNull<TrapHandler>, PhantomData<T>);

impl<T: 'static> EntireContext<T> {
    /// 分离完整路径上下文和快速路径消息。
    #[inline]
    pub fn split(mut self) -> (EntireContextSeparated, FastMail<T>) {
        let mail = unsafe { &mut *self.0.as_mut().locate_fast_mail() };
        let mut handler = self.0;
        forget(self);
        (
            EntireContextSeparated(unsafe { handler.as_mut() }),
            FastMail(mail),
        )
    }
}

/// 如果没有调用分离，快速路径消息对象可以直接释放。
impl<T: 'static> Drop for EntireContext<T> {
    #[inline]
    fn drop(&mut self) {
        unsafe { (*self.0.as_mut().locate_fast_mail::<T>()).assume_init_drop() }
    }
}

/// 分离了快速路径消息的完整路径上下文。
#[repr(transparent)]
pub struct EntireContextSeparated(&'static mut TrapHandler);

impl EntireContextSeparated {
    /// 获取控制流上下文。
    #[inline]
    pub fn regs(&mut self) -> &mut FlowContext {
        unsafe { self.0.context.as_mut() }
    }

    /// 从完整路径恢复。
    #[inline]
    pub fn restore(self) -> EntireResult {
        EntireResult::Restore
    }
}

/// 快速路径消息。
#[repr(transparent)]
pub struct FastMail<T: 'static>(&'static mut MaybeUninit<T>);

impl<T: 'static> FastMail<T> {
    /// 获取快速路径消息。
    #[inline]
    pub fn get(self) -> T {
        let ans = unsafe { core::mem::replace(self.0, MaybeUninit::uninit()).assume_init() };
        forget(self);
        ans
    }
}

impl<T: 'static> Deref for FastMail<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { self.0.assume_init_ref() }
    }
}

impl<T: 'static> DerefMut for FastMail<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.0.assume_init_mut() }
    }
}

/// 快速路径消息如果未被取走，将自动释放。
impl<T: 'static> Drop for FastMail<T> {
    #[inline]
    fn drop(&mut self) {
        unsafe { self.0.assume_init_drop() }
    }
}

/// 完整路径处理结果。
#[repr(usize)]
pub enum EntireResult {
    /// 调用新上下文，只需设置 2 个或更少参数。
    FastCall = 0,
    /// 调用新上下文，需要设置超过 2 个参数。
    Call = 1,
    /// 切换到另一个上下文或从完整路径恢复。
    Restore = 3,
}
