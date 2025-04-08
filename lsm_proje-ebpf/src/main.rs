#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_task_btf, r#gen::bpf_task_pt_regs}, macros::lsm, programs::LsmContext
};
use aya_log_ebpf::info;
use core::ptr;

mod vmlinux;
use vmlinux::{task_struct, cred, kernel_cap_t, pt_regs};

const SYSCALL_UNSHARE_X86_64: u64 = 272;
const CLONE_NEWUSER: u64 = 0x10000000;
const CAP_SYS_ADMIN: usize = 21;
const EPERM: i32 = 1;



#[lsm(hook = "cred_prepare")]
pub fn cred_prepare(ctx: LsmContext) -> i32 {
    match try_cred_prepare(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_cred_prepare(ctx: LsmContext) -> Result<i32, i32> {
    unsafe {
        let task = bpf_get_current_task_btf() as *mut task_struct;
        if task.is_null() {
            return Ok(0);
        }

        let cred = (*task).real_cred;
        if cred.is_null() {
            return Ok(0);
        }

        let regs = bpf_task_pt_regs(task as *mut aya_ebpf::bindings::task_struct) as *const pt_regs;
        if regs.is_null() {
            return Ok(0);
        }

        let syscall = ptr::read_volatile(&(*regs).orig_ax);
        if syscall != SYSCALL_UNSHARE_X86_64 {
            return Ok(0);
        }

        let flags = ptr::read_volatile(&(*regs).di);
        if (flags & CLONE_NEWUSER) == 0 {
            return Ok(0);
        }

        let caps = (*cred).cap_effective.cap;
        let index = CAP_SYS_ADMIN / 32;
        let mask = 1u32 << (CAP_SYS_ADMIN % 32);

        if (caps[index] & mask) != 0 {
            return Ok(0);
        }

        info!(&ctx, "Blocking unshare(CLONE_NEWUSER)");
        Err(-EPERM)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
