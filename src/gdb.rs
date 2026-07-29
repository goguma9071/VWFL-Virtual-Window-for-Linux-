use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::base::single_register_access::SingleRegisterAccessOps;
use gdbstub::target::{Target, TargetResult};
use gdbstub::target::ext::breakpoints::{Breakpoints, SwBreakpoint, BreakpointsOps};
use gdbstub::target::ext::base::multithread::{MultiThreadBase, MultiThreadResume, MultiThreadResumeOps, MultiThreadSingleStep, MultiThreadSingleStepOps};
use gdbstub_arch::x86::reg::X86_64CoreRegs;
use crate::vm::Vm;
use gdbstub::common::Tid;

#[derive(Clone, Copy, Debug)]
pub enum GdbResumeAction {
    Continue,
    Step,
}

pub struct VwflTarget<'a> {
    pub vm: &'a mut Vm,
    pub resume_action: Option<GdbResumeAction>,
}

impl<'a> VwflTarget<'a> {
    fn virt_to_phys(&self, vaddr: u64) -> u64 {
        let sregs = match self.vm.vcpu_fd.get_sregs() {
            Ok(s) => s,
            Err(_) => return vaddr,
        };
        
        let cr3 = sregs.cr3;
        let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;

        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let mut entry = [0u8; 8];
        if self.vm.read_memory((pml4_base + pml4_idx * 8) as usize, &mut entry).is_err() { return vaddr; }
        let pml4e = u64::from_le_bytes(entry);
        if pml4e & 1 == 0 { return vaddr; }

        let pdpt_base = pml4e & 0x000F_FFFF_FFFF_F000;
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        if self.vm.read_memory((pdpt_base + pdpt_idx * 8) as usize, &mut entry).is_err() { return vaddr; }
        let pdpte = u64::from_le_bytes(entry);
        if pdpte & 1 == 0 { return vaddr; }
        if pdpte & 0x80 != 0 {
            return (pdpte & 0x000F_FFFF_C000_0000) | (vaddr & 0x3FFF_FFFF);
        }

        let pd_base = pdpte & 0x000F_FFFF_FFFF_F000;
        let pd_idx = (vaddr >> 21) & 0x1FF;
        if self.vm.read_memory((pd_base + pd_idx * 8) as usize, &mut entry).is_err() { return vaddr; }
        let pde = u64::from_le_bytes(entry);
        if pde & 1 == 0 { return vaddr; }
        if pde & 0x80 != 0 {
            return (pde & 0x000F_FFFF_FFE0_0000) | (vaddr & 0x1F_FFFF);
        }

        let pt_base = pde & 0x000F_FFFF_FFFF_F000;
        let pt_idx = (vaddr >> 12) & 0x1FF;
        if self.vm.read_memory((pt_base + pt_idx * 8) as usize, &mut entry).is_err() { return vaddr; }
        let pte = u64::from_le_bytes(entry);
        if pte & 1 == 0 { return vaddr; }

        (pte & 0x000F_FFFF_FFFF_F000) | (vaddr & 0xFFF)
    }
}

impl<'a> Target for VwflTarget<'a> {
    type Arch = gdbstub_arch::x86::X86_64_SSE;
    type Error = &'static str;

    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::MultiThread(self)
    }

    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }
}

impl<'a> MultiThreadBase for VwflTarget<'a> {
    fn read_registers(&mut self, regs: &mut X86_64CoreRegs, _tid: Tid) -> TargetResult<(), Self> {
        let kvm_regs = self.vm.vcpu_fd.get_regs().map_err(|_| ())?;
        let sregs = self.vm.vcpu_fd.get_sregs().map_err(|_| ())?;
        
        regs.regs[0] = kvm_regs.rax;
        regs.regs[1] = kvm_regs.rbx;
        regs.regs[2] = kvm_regs.rcx;
        regs.regs[3] = kvm_regs.rdx;
        regs.regs[4] = kvm_regs.rsi;
        regs.regs[5] = kvm_regs.rdi;
        regs.regs[6] = kvm_regs.rbp;
        regs.regs[7] = kvm_regs.rsp;
        regs.regs[8] = kvm_regs.r8;
        regs.regs[9] = kvm_regs.r9;
        regs.regs[10] = kvm_regs.r10;
        regs.regs[11] = kvm_regs.r11;
        regs.regs[12] = kvm_regs.r12;
        regs.regs[13] = kvm_regs.r13;
        regs.regs[14] = kvm_regs.r14;
        regs.regs[15] = kvm_regs.r15;
        regs.rip = kvm_regs.rip;
        regs.eflags = kvm_regs.rflags as u32;

        // 세그먼트 레지스터 보고 (GDB stub 규격에 맞춤)
        regs.segments.cs = sregs.cs.selector as u32;
        regs.segments.ss = sregs.ss.selector as u32;
        regs.segments.ds = sregs.ds.selector as u32;
        regs.segments.es = sregs.es.selector as u32;
        regs.segments.fs = sregs.fs.selector as u32;
        regs.segments.gs = sregs.gs.selector as u32;
        
        Ok(())
    }

    fn write_registers(&mut self, regs: &X86_64CoreRegs, _tid: Tid) -> TargetResult<(), Self> {
        let mut kvm_regs = self.vm.vcpu_fd.get_regs().map_err(|_| ())?;
        kvm_regs.rax = regs.regs[0];
        kvm_regs.rbx = regs.regs[1];
        kvm_regs.rcx = regs.regs[2];
        kvm_regs.rdx = regs.regs[3];
        kvm_regs.rsi = regs.regs[4];
        kvm_regs.rdi = regs.regs[5];
        kvm_regs.rbp = regs.regs[6];
        kvm_regs.rsp = regs.regs[7];
        kvm_regs.r8 = regs.regs[8];
        kvm_regs.r9 = regs.regs[9];
        kvm_regs.r10 = regs.regs[10];
        kvm_regs.r11 = regs.regs[11];
        kvm_regs.r12 = regs.regs[12];
        kvm_regs.r13 = regs.regs[13];
        kvm_regs.r14 = regs.regs[14];
        kvm_regs.r15 = regs.regs[15];
        kvm_regs.rip = regs.rip;
        kvm_regs.rflags = regs.eflags as u64;
        self.vm.vcpu_fd.set_regs(&kvm_regs).map_err(|_| ())?;
        Ok(())
    }

    fn read_addrs(&mut self, start_addr: u64, data: &mut [u8], _tid: Tid) -> TargetResult<usize, Self> {
        let paddr = self.virt_to_phys(start_addr);
        if let Err(_) = self.vm.read_memory(paddr as usize, data) {
            return Ok(0);
        }
        Ok(data.len())
    }

    fn write_addrs(&mut self, start_addr: u64, data: &[u8], _tid: Tid) -> TargetResult<(), Self> {
        let paddr = self.virt_to_phys(start_addr);
        self.vm.write_memory(paddr as usize, data).map_err(|_| ())?;
        Ok(())
    }

    fn list_active_threads(&mut self, cb: &mut dyn FnMut(Tid)) -> Result<(), Self::Error> {
        cb(Tid::new(1).unwrap());
        Ok(())
    }

    fn support_resume(&mut self) -> Option<MultiThreadResumeOps<'_, Self>> {
        Some(self)
    }

    fn support_single_register_access(&mut self) -> Option<SingleRegisterAccessOps<'_, Tid, Self>> {
        None
    }
}

impl<'a> MultiThreadResume for VwflTarget<'a> {
    fn clear_resume_actions(&mut self) -> Result<(), Self::Error> {
        self.resume_action = None;
        Ok(())
    }

    fn set_resume_action_continue(&mut self, _tid: Tid, _signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
        self.resume_action = Some(GdbResumeAction::Continue);
        Ok(())
    }

    fn resume(&mut self) -> Result<(), Self::Error> {
        let mut control = kvm_bindings::KVM_GUESTDBG_ENABLE | kvm_bindings::KVM_GUESTDBG_USE_SW_BP;
        if let Some(GdbResumeAction::Step) = self.resume_action {
            control |= kvm_bindings::KVM_GUESTDBG_SINGLESTEP;
        }
        let dbg = kvm_bindings::kvm_guest_debug {
            control,
            ..Default::default()
        };
        self.vm.vcpu_fd.set_guest_debug(&dbg).map_err(|_| "KVM Debug Error")?;
        Ok(())
    }

    fn support_single_step(&mut self) -> Option<MultiThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl<'a> MultiThreadSingleStep for VwflTarget<'a> {
    fn set_resume_action_step(&mut self, _tid: Tid, _signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
        self.resume_action = Some(GdbResumeAction::Step);
        Ok(())
    }
}

impl<'a> Breakpoints for VwflTarget<'a> {
    fn support_sw_breakpoint(&mut self) -> Option<gdbstub::target::ext::breakpoints::SwBreakpointOps<'_, Self>> {
        Some(self)
    }
}

impl<'a> SwBreakpoint for VwflTarget<'a> {
    fn add_sw_breakpoint(&mut self, _addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        Ok(true)
    }

    fn remove_sw_breakpoint(&mut self, _addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        Ok(true)
    }
}
