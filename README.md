﻿# 快速陷入处理

[![CI](https://github.com/YdrMaster/fast-trap/actions/workflows/workflow.yml/badge.svg?branch=main)](https://github.com/YdrMaster/fast-trap/actions)
[![issue](https://img.shields.io/github/issues/YdrMaster/fast-trap)](https://github.com/YdrMaster/fast-trap/issues)
![license](https://img.shields.io/github/license/YdrMaster/fast-trap)

这个库提供一套裸机应用程序陷入处理流程的框架，旨在保证处理性能的同时尽量复用代码。

## 目录

- [概念](#概念)
  - [陷入向量](#陷入向量)
  - [陷入栈](#陷入栈)
  - [陷入快速路径](#陷入快速路径)
  - [控制流切换](#控制流切换)
  - [根控制流](#根控制流)

## 概念

**陷入**是硬件的异步机制，由于异常或中断，一个连续的控制流会被硬件打断，然后从另一个位置继续开始。本文将发生陷入的控制流称为**现场控制流**，将由于陷入而到达的控制流称为**陷入控制流**。

对于现场控制流和陷入控制流的关系有 2 种认识：

1. 二者是对等的控制流；
2. 二者不是对等的，而是性质不同的 2 种控制流；

本文基于观点 #2 展开。即，本文认为，发生陷入导致控制流产生了 2 级结构。为方便叙述，规定：对于一次陷入产生的现场控制流和陷入控制流，将现场控制流称为低级控制流，陷入控制流称为高级控制流。

如果软件支持，在陷入控制流上还能再次发生陷入（这并不罕见），这一般被称为**陷入嵌套**。这些嵌套结构使控制流形成了时间上的树状结构。依本文的规定，可以用相对的级别来描述这些控制流的关系。下图展示了一个控制流发生 2 级嵌套的陷入时，控制流的转移过程：

```plaintext
root flow ----x----------x----> t
             / \        / \
            /   \      /   \_______________
           /     \    /                    \
trap Lv.1 ·------>   ·-----x----------x---->
                          / \        / \
                         /   \      /   \
                        /     \    /     \
trap Lv.2              ·------>   ·------>
```

> - 图中箭头方向表示时序方向；
> - `·` 表示控制流从空白的栈开始，或者说没有**内生状态**，即所有状态都来自外部指定，可以理解为广义的参数；
> - `x` 表示一次陷入，一般的陷入都是硬件引起的（包括软中断、`ecall` 和 `ebreak`），但也并非绝对。凡是以特定方式进入高级控制流的过程，就认为是广义的陷入；

这个库定义了如何在嵌套的陷入中管理多个控制流。所有控制流被分为由用户主动构造的**根控制流**和硬件陷入产生的**非根控制流**。对于根控制流，库并不干涉，用户可以自由地定义其结构和管理方式。非根控制流的基本结构被库限定，以实现对其切换操作的封装。

### 陷入向量

库提供了一个陷入处理例程，这个例程的入口需要加载到硬件。使用 `load_direct_trap_entry` 函数可以完成这个操作。这个函数将陷入配置为直接模式。若要使用中断向量表，可以通过 `trap` 函数找到入口地址。

陷入向量的设置是独立于陷入的，只需要初始化一次。所以也可以将陷入向量指向另一个位置以关闭整个库的功能。

### 陷入栈

控制流上要运行高级语言，必须有一个栈。陷入产生一个新的控制流，必然伴随着栈切换。在陷入发生前，必须先为其准备一个**陷入栈**。高级语言的陷入处理函数会运行在这个栈上。

这个库将陷入栈设计成一个在地址空间上连续的内存块。当用户预期陷入将会发生之前（例如从内核切换到用户之前或打开中断之前），需要预先分配一个陷入栈对象，然后将其加载到硬件。这样，一旦陷入发生，硬件就能在两个控制流之间转移。

发生陷入的控制流称为**现场控制流**，处理陷入的控制流称为**陷入控制流**，从现场控制流转移到陷入控制流即**陷入**，从陷入控制流回到现场控制流称为**恢复**。

#### 陷入嵌套

一旦一个陷入发生，控制流将转移到陷入栈的处理函数，同时，中断也被屏蔽。陷入处理可能是缓慢的，由于实时性要求，不能一直关闭中断，也不能排除进一步的异常，这就需要陷入嵌套。在陷入处理函数中，可以构造另一个陷入栈。只要按上述操作将其加载为预备陷入栈，就可以处理陷入控制流上的嵌套陷入了。

#### 陷入栈回收

对于嵌套的陷入栈，高级栈的生命周期是不可能超过低级栈的。

或者，另一种理解是**陷入栈是对控制流的保护**。对于这个库提供的框架来说，陷入、恢复以及任务的切换过程中是不会发生陷入的，所以也不需要保护。因此，所有控制流都是**结构化的**。对于一般的情况，只需要将低级栈的 RAII 对象限定在高级语言陷入处理上下文中，就可以在低级陷入完成时自动回收陷入栈。

### 陷入快速路径

从发生陷入，到第一次进入高级语言处理函数，之间执行的指令就是陷入的**开销**。即发生一次陷入的必要代价。必须尽量降低这个开销，才能提升陷入处理的实时性。之所以要执行这些指令，是因为高级语言的编译器会自动安排寄存器的用法，而陷入发生时，通用寄存器里正保存着陷入现场的信息，必须将这些寄存器的值转存以保护现场。

但对于编译器来说，寄存器分为调用者保存的和被调用者保存的，被调用者保存的寄存器，编译器会自动保护。如果陷入处理不关心这些寄存器的值就不需要在固定的汇编里保存它们。幸好，陷入处理常常不关心它们。因此，陷入发生的第一时间，可以只保存一小部分寄存器以获得最优的处理延迟，这就是所谓的**陷入快速路径**。

在快速路径中，只能查、改陷入现场的一部分寄存器。对于 RISC-V 来说，这些寄存器包括：返回地址 `ra`、指针 `sp`、`gp` 和 `tp`，以及所有的临时寄存器 `t0-t6` 和参数寄存器 `a0-a7`。其中参数寄存器是按照调用约定直接传递到高级语言内的，并未保存到上下文对象。另外，陷入栈的定义保证了发生陷入时一定会进入一个干净的上下文，不需要恢复。所以，从发生陷入到进入快速路径，只需要 14 个指令（其中 11 个是访存的）：

```rust
// 换栈
"   csrrw sp, sscratch, sp",
// 加载上下文指针
"   sd    a0,  2*8(sp)
    ld    a0,  0*8(sp)
",
// 保存尽量少的寄存器
"   sd    ra,  0*8(a0)
    sd    t0,  1*8(a0)
    sd    t1,  2*8(a0)
    sd    t2,  3*8(a0)
    sd    t3,  4*8(a0)
    sd    t4,  5*8(a0)
    sd    t5,  6*8(a0)
    sd    t6,  7*8(a0)
",
// 调用快速路径函数
"   mv    a0,      sp
    ld    ra,  1*8(sp)
    jalr  ra
",
```

如果处理流程关心未保存的那些寄存器，就必须离开快速路径，保存剩余的寄存器再重新进入，这称为**陷入完整路径**。这种情况一般出现在需要切换控制流的陷入，例如时钟中断或 `yield` 类型的系统调用，因为这时必须将完整的陷入现场打包保存。因此，快速路径函数的定义如下：

```rust
type FastHandler = extern "C" fn(
    ctx: FastContext,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
) -> FastResult;
```

它可以通过返回值通知框架是否需要进入完整路径。然而，快速路径中可能还有一些计算结果需要传递给完整路径继续处理，但这两个部分被分隔开了，无法通过栈传递。因此，库模仿协程的方式，在陷入栈上预留了一个虚拟栈区用于在从快速路径转移到完整路径的过程中暂存信息，即陷入栈的泛型 `T`。快速路径可以设置一个 `T` 对象，然后在完整路径中读取。

快速路径的返回值 `FastResult` 有多种取值：

```rust
enum FastResult {
    /// 调用新上下文，只需设置 2 个或更少参数。
    Call,
    /// 调用新上下文，需要设置超过 2 个参数。
    ComplexCall,
    /// 从快速路径直接返回。
    Restore,
    /// 直接切换到另一个上下文。
    Switch,
    /// 调用完整路径函数。
    Continue,
}

```

这会控制汇编执行不同的切换操作，以减少离开陷入控制流消耗的指令数。

### 控制流切换

每当一个控制流被陷入打断，机器会进入一个新的陷入控制流，而发生陷入的控制流则转化为陷入控制流里的一个现场对象。陷入控制流可以修改对象，以影响原控制流的状态。如果将原控制流的现场完全收集并保存，然后换入另一个对象，就实现了控制流的切换。以下图表示的控制流发生陷入时的转移结构图为例：

```plaintext
root flow α----1--------->2
              / \        /
             /   \      /
            /     \    /
trap Lv.1  β------>   γ-->1
                         /
                        /
                       /
trap Lv.2             δ-->1
```

> 图中用小写希腊字母表示控制流，用阿拉伯数字表示发生陷入的推进位置。例如，控制流 α 在 α1 点处发生陷入，切换到 β；β 没有发生陷入，运行结束后回到 α1 点继续运行。

假设当软件运行到 δ1 时，发现了一个无法继续运行的情况（例如等待互斥锁），必须切换到另一个控制流运行。则用户可以在处理路径中将 δ 控制流打包保存，然后切换到另一个控制流 ε1 点继续运行，如图所示：

```plaintext
root flow α----1--------->2
              / \        /
             /   \      /
            /     \    /
trap Lv.1  β------>   γ-->1   ε-----1---->
                         /         /
                        /   ______/
                       /   /
trap Lv.2             δ-->1
```

要注意的是，当控制流 δ 被封存，同时被封存的还有 γ 和 α，因为它们的现场对象递归地属于 δ。

> 对于 Rust 语言的所有权模型来说，这个操作导致了奇特的所有权反转现象。即 δ 控制流所在的栈所有权位于 γ 控制流，但封存时，γ 的栈依赖于 δ 现场对象持有所有权以维持生命周期。
>
> 这是因为，通常的栈具有最大的生命周期，同时也是最大的所有权拥有者，以至于通常栈上对象的所有权分析只关注时序。但如果栈本身具有非全局的所有权（例如一般的线程栈）栈上对象的所有权分析就不能省略了。在这个库中，由于发生陷入的现场一定会被打包传递到陷入栈上，类似于在 std 环境将 `ScopedJoinHandle` 的引用传递到其指向的线程内。因此一旦现场对象丢失，整个多级控制流会因为互相持有而无法释放，发生泄露。

另外，虽然上图示意的 ε 控制流位于 Lv.1，但实际上陷入的级别是由控制流相对其根的距离决定的，而在切换时，它们却由于**共享陷入栈**而在叶子对齐。ε 可能本身是一个根控制流，也可能是在陷入过程中被封存的陷入控制流，这不影响切换到它的过程。唯一确定的是发生切换的 δ 不会是根控制流，因为一致性的切换一定发生在从陷入返回时，根控制流无法再返回了。

### 根控制流

用户可以自由设计根控制流，或者在根控制流中做任何事。只需要通过库定义的上下文结构体与即可与库交互。上下文结构体的定义如下：

```rust
struct FlowContext {
    pub ra: usize,
    pub t: [usize; 7],
    pub a: [usize; 8],
    pub s: [usize; 12],
    pub gp: usize,
    pub tp: usize,
    pub sp: usize,
    pub pc: usize,
}
```

包括 31 个通用寄存器和 pc 指针。其他系统状态寄存器，例如 RISC-V 的 `sstatus`、`stval`、`scause` 等，由用户自行管理。
