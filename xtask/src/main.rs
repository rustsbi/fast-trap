#[macro_use]
extern crate clap;

use clap::Parser;
use once_cell::sync::Lazy;
use os_xtask_utils::{BinUtil, Cargo, CommandExt, Qemu};
use std::{
    fs,
    path::{Path, PathBuf},
};

static PROJECT: Lazy<&'static Path> =
    Lazy::new(|| Path::new(std::env!("CARGO_MANIFEST_DIR")).parent().unwrap());

#[derive(Parser)]
#[clap(name = "try-rtos")]
#[clap(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Make(BuildArgs),
    Asm(AsmArgs),
    Qemu(QemuArgs),
}

fn main() {
    use Commands::*;
    match Cli::parse().command {
        Make(args) => {
            args.make();
        }
        Asm(args) => args.dump(),
        Qemu(args) => args.run(),
    }
}

#[derive(Clone, Copy, Debug)]
enum Arch {
    RISCV32(Mode),
    RISCV64(Mode),
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Machine,
    Supervisor,
}

impl From<&'_ str> for Arch {
    #[inline]
    fn from(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "rv32:m" => Arch::RISCV32(Mode::Machine),
            "rv32:s" => Arch::RISCV32(Mode::Supervisor),
            "rv64:m" => Arch::RISCV64(Mode::Machine),
            "rv64:s" => Arch::RISCV64(Mode::Supervisor),
            _ => panic!(),
        }
    }
}

#[derive(Args)]
struct BuildArgs {
    #[clap(short, long)]
    arch: Arch,
    /// log level
    #[clap(long)]
    log: Option<String>,
    /// build in debug mode
    #[clap(long)]
    debug: bool,
}

impl BuildArgs {
    fn make(&self) -> PathBuf {
        let package = "test-app";
        let (target, feature) = match self.arch {
            Arch::RISCV32(Mode::Machine) => ("riscv32imac-unknown-none-elf", ["m-mode"]),
            Arch::RISCV32(Mode::Supervisor) => ("riscv32imac-unknown-none-elf", ["s-mode"]),
            Arch::RISCV64(Mode::Machine) => ("riscv64imac-unknown-none-elf", ["m-mode"]),
            Arch::RISCV64(Mode::Supervisor) => ("riscv64imac-unknown-none-elf", ["s-mode"]),
        };
        Cargo::build()
            .package(package)
            .features(true, feature)
            .optional(&self.log, |cargo, log| {
                cargo.env("LOG", log);
            })
            .conditional(!self.debug, |cargo| {
                cargo.release();
            })
            .target(target)
            .invoke();
        PROJECT
            .join("target")
            .join(target)
            .join(if self.debug { "debug" } else { "release" })
            .join(package)
    }
}

#[derive(Args)]
struct AsmArgs {
    #[clap(flatten)]
    build: BuildArgs,
    /// Output file.
    #[clap(short, long)]
    output: Option<String>,
}

impl AsmArgs {
    fn dump(self) {
        let elf = self.build.make();
        let out = PROJECT.join(self.output.unwrap_or("test-app.asm".into()));
        println!("Asm file dumps to '{}'.", out.display());
        fs::write(out, BinUtil::objdump().arg(elf).arg("-d").output().stdout).unwrap();
    }
}

#[derive(Args)]
struct QemuArgs {
    #[clap(flatten)]
    build: BuildArgs,
    /// Port for gdb to connect. If set, qemu will block and wait gdb to connect.
    #[clap(long)]
    gdb: Option<u16>,
}

impl QemuArgs {
    fn run(self) {
        let elf = self.build.make();
        let (arch, mode) = match self.build.arch {
            Arch::RISCV32(Mode::Machine) => ("riscv32", "-bios"),
            Arch::RISCV32(Mode::Supervisor) => ("riscv32", "-kernel"),
            Arch::RISCV64(Mode::Machine) => ("riscv64", "-bios"),
            Arch::RISCV64(Mode::Supervisor) => ("riscv64", "-kernel"),
        };
        Qemu::system(arch)
            .args(["-machine", "virt"])
            .arg("-nographic")
            .arg(mode)
            .arg(objcopy(elf, true))
            .args(["-serial", "mon:stdio"])
            .optional(&self.gdb, |qemu, gdb| {
                qemu.args(["-S", "-gdb", &format!("tcp::{gdb}")]);
            })
            .invoke();
    }
}

fn objcopy(elf: impl AsRef<Path>, binary: bool) -> PathBuf {
    let elf = elf.as_ref();
    let bin = elf.with_extension("bin");
    BinUtil::objcopy()
        .arg(elf)
        .arg("--strip-all")
        .conditional(binary, |binutil| {
            binutil.args(["-O", "binary"]);
        })
        .arg(&bin)
        .invoke();
    bin
}
