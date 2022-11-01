﻿# 快速陷入处理

[![CI](https://github.com/YdrMaster/fast-trap/actions/workflows/workflow.yml/badge.svg?branch=main)](https://github.com/YdrMaster/fast-trap/actions)
[![issue](https://img.shields.io/github/issues/YdrMaster/fast-trap)](https://github.com/YdrMaster/fast-trap/issues)
![license](https://img.shields.io/github/license/YdrMaster/fast-trap)

这个库提供一套裸机应用程序陷入处理流程的框架，旨在保证处理性能的同时尽量复用代码。

> **感谢：2022 系统能力赛，哈工大（深圳），[FTL-OS](https://gitlab.eduxiji.net/DarkAngelEX/oskernel2022-ftlos) 提供灵感**

## 目录

- [概念](#概念)
- [术语](#术语)
- [高效转移](#高效转移)
- [陷入向量和突发寄存器](#陷入向量和突发寄存器)
- [陷入栈](#陷入栈)
- [陷入快速路径](#陷入快速路径)
- [切换现场](#切换现场)
- [任务兼容性](#任务兼容性)
- [陷入服务程序的一致抽象](#陷入服务程序的一致抽象)

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
trap Lv.1 o------>o  o-----x----------x---->o
                          / \        / \
                         /   \      /   \
                        /     \    /     \
trap Lv.2              o------>o  o------>o
```

关于这幅图，需要注意以下 3 点：

1. 图中箭头方向表示时序方向，不表示空间位置。即使是循环，也画成一条线；
2. `x` 表示一次陷入，一般的陷入都是硬件引起的（包括软中断、`ecall` 和 `ebreak`），但也并非绝对。凡是以特定方式进入高级控制流的过程，就认为是广义的陷入；
3. `o` 表示控制流具有空白的栈。箭头起点的 `o` 表示控制流从空白的栈开始，或者说没有**内生状态**，所有状态都来自外部指定，这些外部指定的状态可以理解为广义的参数。箭头指向的 `o` 表示控制流的生命周期结束，栈上所有信息都被清空，所有权转移或释放；

这个库定义了如何在嵌套的陷入中管理多个控制流。所有控制流被分为由用户主动构造的**根控制流**和硬件陷入产生的**非根控制流**。对于根控制流，库并不干涉，用户可以自由地定义其结构和管理方式。非根控制流的基本结构被库限定，以实现对其操作的封装。

## 术语

本文把**陷入**当作名词，描述硬件控制或模拟硬件控制，直接从一个控制流转移到另一个控制流的过程。从陷入控制流回到现场控制流的过程称为**恢复**。可以用**发生陷入**和**执行恢复**来指代这两个动作，以强调陷入通常是突发的、被动的，而恢复是自然的、主动的。

为了区分，**切换**只用于描述软件明确定义的**任务**之间的切换，控制流发生陷入和恢复的动作统一称为**转移**。

## 高效转移

与任意的根控制流相比，非根控制流强调**空入空出**。也就是说，只要发生陷入，一定转移到一个空的控制流，而运行完后则一定清空状态再执行恢复。这个设计是为了降低转移的开销。

如果转移发生在两个非空白的控制流之间，则必须先保存出控制流的现场，再恢复入控制流的现场，然后才能恢复入控制流执行。对于 RISC-V 这样有大量通用寄存器的架构来说，保存和恢复是沉重的负担，至少需要 `(32 - 1) × 2 = 62` 个访存的指令。但如果有一边是空白的控制流，就意味着不需要保存或恢复其现场，转移的开销就会降低一半。

恰好，保持陷入控制流的空入空出是容易的。因为陷入控制流是陷入发生前预先指定的，完全可以总是指定到空白的控制流。而执行恢复是主动的，有充分的时机在恢复前清空状态。因此，本文选择将陷入控制流以非根控制流的形式固定下来，实现控制流转移的高效封装。

如果读者了解**协程异步**，也许可以发现，非根控制流是介于**绿色线程/有栈协程**和**无栈协程**之间的东西。当它被抢占，它表现得像一个一般的线程，但当它开始和结束的时候，它由于具有特殊的状态而降低了开销。这和协程由于只能在预定的让出点转移，而能预编码转移过程以减小开销的方案如出一辙。

## 陷入向量和突发寄存器

硬件上（ARM、RISC-V M & H & S），陷入和恢复的转移行为是由陷入向量（trap vec）和突发寄存器（scratch）决定的。当硬件发现陷入条件（异常和中断），pc 将指向陷入向量。而刚到达陷入向量时，软件处于举目无亲的状态，所有通用寄存器都因为存放着现场而不能操作，只有预设的突发寄存器可以读写。突发寄存器里必须存放一个指向一些预留空间的指针，以供保存现场。

以上描述是现有的硬件设计决定的，对于软件来说是一种必然。软件能做的只是在可能的陷入发生之前把它们准备好。库提供了一个陷入处理例程，使用 `load_direct_trap_entry` 函数可以以直接模式将其配置到硬件。若要使用中断向量表，可以通过 `trap` 函数找到入口地址。

> 中断向量表是很有意义的，因为中断是外部事件触发的，比异常更加不可预测，中断几乎总是需要封存现场并切换任务，尤其是时钟中断。但异常的解决则非常多样，有可能因为十分简单而能更快地处理。进一步的讨论见[陷入快速路径](#陷入快速路径)。

陷入向量的设置是独立于陷入的，如果没有用于其他操作就只需要初始化一次。而突发寄存器每次陷入都会读写。[下一节](陷入栈)介绍了保存在突发寄存器里的陷入栈对象，包括其结构、生命周期、复用，以及如何构造、加载、卸载和回收。

## 陷入栈

突发寄存器保存着一个指针，同时这也是陷入发生的第一时间唯一可访问的动态数据。虽然任何静态链接的数据也都是可以找到和使用的，但出于安全性考虑，将所有需要用到的东西打包放在一起是更好的选择。

这个库将陷入栈设计成一个在地址空间上连续的内存块。当用户预期陷入将会发生之前（例如从内核切换到用户之前或打开中断之前），需要预先分配一个陷入栈对象，然后将其加载到突发寄存器。这样，一旦陷入发生，硬件就能在两个控制流之间转移。内存块可以用用实现这个特质的类型表示：

```rust
trait TrapStackBlock: 'static + AsRef<[u8]> + AsMut<[u8]> {}
```

陷入栈内部分为 3 个部分，从高地址到低地址，分别是：

| 陷入处理上下文 | 栈空间 | 快速路径消息
| - | - | -

- 陷入处理上下文是一个 `extern "C"` 的结构体，其内部以固定的结构保存着一组指针，可以在汇编里使用。用于保存寄存器的预留空间，以及高级语言函数指针都是在这里指定的；
- 栈空间就是高级语言使用的栈。由于栈指针是从高到低增长，发生陷入时，只要将指向陷入上下文首地址的指针从突发寄存器加载到栈指针寄存器，就能同时访问陷入上下文和栈空间，这也节约了几条指令；
- 快速路径消息用于一个进一步降低陷入开销的**陷入快速路径**设计，其详细信息将在[下一节](#陷入快速路径)介绍；

### 陷入栈的生命周期

陷入栈是用于**保护现场**的，需要在任何陷入发生之前预先构造和加载。构造陷入栈就是分配栈所需的空间并初始化处理上下文，可以使用这个方法完成：

```rust
fn new(
    block: impl TrapStackBlock,
    context_ptr: NonNull<FlowContext>,
    fast_handler: FastHandler,
) -> Result<Self, IllegalStack>
```

- `block` 是用作栈的内存块；
- `context_ptr` 是用于保存控制流上下文（通用寄存器）的对象指针，用户需要自己控制其生命周期；
- `fast_handler` 是快速路径函数，一个 `extern "C"` 的函数指针，将由汇编调用；

这个方法将先检查内存块是否够大，然后在其上初始化陷入处理上下文。如果成功，将返回一个 `FreeTrapStack` 对象。这个类型表示一个游离的陷入栈，还没有加载到突发寄存器，因此只是个内存块，不会产生作用。如果这个对象被释放，它所在的内存块递归地释放。

调用游离陷入栈的 `load` 方法可以将它加载到突发寄存器。返回一个 `LoadedTrapStack` 对象，表示陷入栈已加载。通过已加载陷入栈对象可以找到加载前原本在突发寄存器里的值，这可能是重要的。如果已加载的陷入栈被释放，它会先卸载陷入栈并将突发寄存器原本的值换回，然后释放陷入栈。因此陷入栈总能安全地使用，不会泄露。

陷入栈可以随时构造，随时释放，游离栈和加载栈的世代交替保证栈对象总在监管之下。这提供了控制流保护的便利性。任何控制流，只要有可能发生陷入，就可以提前准备一个陷入栈来保护，这个操作的开销只取决于分配空间的开销，而分配规整、等大的内存块差不多是最容易优化的分配了。这为线程、协程的混合调度提供了可能，细节将在下文描述。

实际上，陷入栈的生命周期远比上文描述的复杂。因为陷入栈就是用来处理陷入的，一旦发生陷入，原本的栈就会被打包换出，则原本的栈上用于追踪高级陷入栈生命周期的对象就会失效。如果陷入处理决定**切换**到另一个控制流而非恢复原本的控制流，那么在新的控制流上看到的已加载陷入栈会是做出切换决定的那一个，而不是它曾经加载的……然而，`FreeTrapStack` 和 `LoadedTrapStack` 的抽象利用突发寄存器的不变性，简单地保证陷入栈的创建和释放是成对的，因此这些细节将对用户透明。同一个陷入栈可能被许多不同的任务复用。用户只需注意不要随意修改突发寄存器。如果必须修改突发寄存器，可以同时将陷入向量也移走以暂时关闭库提供的功能，这是很轻量的操作。

只有一个例外：控制流是有可能被丢弃的，一旦丢弃，它的栈上信息也会直接丢失，这是线程抽象最大的缺点。幸好，如果丢弃的是非根控制流，那么它本身就是运行在一个陷入栈上的，因此丢弃它，意味着丢弃它的栈，那么陷入栈仍然保持创建释放成对而没有泄露。这提示用户最好不要在可能丢弃的根控制流上追踪陷入栈，也不要在非根控制流上放置多个陷入栈。这些做法并没有什么意义——因为显然同一时刻只能有一个陷入栈被加载——同时还很危险。

陷入栈可能静默地改变，这个现象提示用户最好不要使用多种不同大小的陷入栈，因为巧妙地使某个陷入恰好发生在某个特殊大小的陷入栈并不是那么容易……追踪某一个陷入栈对象生命周期的工作留给用户自行完成：

> 即得易见平凡，仿照上例显然。留作习题答案略，读者自证不难。
>
> 反之亦然同理，推论自然成立，略去过程 QED，由上可知证毕。
>
> ——[【西江月·证明】](https://www.zhihu.com/question/27705700/answer/37997982)

## 陷入快速路径

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

它可以通过返回值通知框架是否需要进入完整路径。然而，快速路径中可能还有一些计算结果需要传递给完整路径继续处理，但这两个部分被分隔开了，无法通过栈传递。因此，库模仿协程的方式，在陷入栈上预留了一个虚拟栈区用于在从快速路径转移到完整路径的过程中暂存信息，即快速路径消息。快速路径消息放置在栈底，以尽量减少它对栈陷入栈空间的影响。完整路径可以尽快读取它，然后栈指针就能继续安全访问这块空间。

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

## 切换现场

每当一个控制流被陷入打断，机器会进入一个新的陷入控制流，而现场控制流则转化为陷入控制流里的一个现场对象。陷入控制流可以修改对象，以影响原控制流的状态。如果将原控制流的现场完全收集并保存，然后换入另一个对象再恢复，就实现了控制流的切换。以下图表示的控制流发生陷入时的转移结构图为例：

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

> 图中用小写希腊字母表示控制流，用阿拉伯数字表示发生控制流自己观察到的时序。例如，控制流 α 在 α1 点处发生陷入，切换到 β；β 没有发生陷入，运行结束后回到 α 从 α1 点继续运行。

假设当软件运行到 δ1 时，发现了一个无法继续运行的情况（例如等待互斥锁），必须切换到另一个控制流运行。则用户可以在处理路径中将 δ 控制流打包保存，然后切换到另一个控制流 ε1 点继续运行，如图所示：

```plaintext
root flow α----1--------->2
              / \        /
             /   \      /
            /     \    /
trap Lv.1  β------>   γ-->1   ε----1---->
                         /        /
                        /   _____/
                       /   /
trap Lv.2             δ-->1
```

要注意的是，当控制流 δ 被封存，同时被封存的还有 γ 和 α，因为它们的现场对象递归地属于 δ。但这些对象的所有权管理需要用户自行完成。

## 任务兼容性

如前所述，嵌入栈的创建和控制是自由的，这意味着本文所述的模式对很多东西都适用。换句话说，这个库并不关心**任务**的定义，它高度自由，完全是业务决定的。对于 Rust 来说，可能有这样一些任务的定义：

1. 函数调用（unikernel、embedded）
2. 协程 = `Future::poll` 的函数调用
3. 内核线程
4. 用户线程
5. 进程

这些任务类型都能任意地切换，只要满足以下 2 个要求：

1. 调度器可以排队和调度出这些类型的任务；
2. 随时设置陷入栈以支持抢占，从而从函数调用切出；

本项目实现了 #2。

把一次切换分为切出和切入两步，每种任务的切出和切入操作如下表：

| 任务              | 切出操作                       | 切入操作
| ---------------- | ----------------------------- | -
| 函数调用           | 函数返回，无操作                | 函数调用，无操作
| 协程              | `Future::poll` 函数返回，无操作 | 传入 `Future::poll`
| 可抢占函数调用/协程 | 函数返回，无操作                | **创建或复用 `LoadedTrapStack`** 再调用
| 内核线程           | **保存上下文等**               | **恢复上下文等**
| 用户线程           | 同内核线程                     | 设置状态寄存器，然后同内核线程
| 进程（单页表）      | 同内核线程                     | 修改地址空间寄存器，然后同用户线程

---

> **加粗的由本项目提供**

下图是一个多种任务混合调度的示例：

```plaintext
root flow (init-proc)--->{fork}     (proc1)---->{exec}----> t
                          /          /           /  \
                         /          /           /    \_____________________________________________
                        /          /           /         +-------------------------------------+   \
trap Lv.1            (trap1)---->{o}        (trap2)----->|----->{interrpt}---->{interrpt}----->|-->{o}
                                                    _____|         /  \           /  \         |
                                                   /     +--------/----\---------/----\--------+
                                        (async-filesystem:read)  /      \       /      \
trap Lv.2                                                     (trap3)-->{o}  (trap4)-->{o}
```

可以看到，在任何级别的控制流上都可以执行任何任务：

1. 陷入视作从线程切出，导致控制流升高一级；
2. 切入线程导致控制流降低一级；
3. 切入新进程就是先修改地址空间寄存器在切入线程；
4. 函数/协程切入或切出不影响控制流级别；
5. 函数/协程的执行是线程的一部分，可以再发生陷入；
6. 切入被中断打断的协程就是切入线程；
7. 过程中随时可以切到完全不同的应用程序（但我不知道怎么画出来）；

## 陷入服务程序的一致抽象

基于本文提出的陷入服务模型，可以对所有基于陷入提供服务的应用程序（各种 SEE、各种 OS 等）建立一致的抽象。

所有这类应用程序可以分为 2 个阶段：

1. 初始化阶段；
2. 服务阶段；

初始化阶段指的是从程序启动开始，到跳转到第一个服务目标结束的过程。在这个阶段，应用程序进行所有必要的初始化，准备好第一个陷入栈并找到第一个服务目标，然后丢弃当前栈直接跳转服务目标。这个阶段执行的工作类似于通常的 bootloader 的工作方式。因此，这个阶段占用的内存，可以在这个阶段结束时完全回收。

服务阶段指的是初始化阶段以后的整个生命周期。这个阶段完全是陷入驱动的，每次发生陷入就进入准备好的陷入栈执行处理流程，平时则完全静默。
