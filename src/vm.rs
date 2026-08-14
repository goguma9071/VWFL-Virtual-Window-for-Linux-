use kvm_ioctls::{Kvm, VmFd, VcpuFd};
use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_LOG_DIRTY_PAGES, kvm_irq_routing_entry, KVM_IRQ_ROUTING_IRQCHIP};
use std::ptr;

pub const MEM_SIZE: usize = 8 * 1024 * 1024 * 1024; // 8GB Total
pub const MMIO_HOLE_START: u64 = 0xC0000000; // 3GB
pub const MMIO_HOLE_SIZE: u64 = 0x40000000;  // 1GB (Hole until 4GB)

pub struct Vm {
    #[allow(dead_code)]
    pub kvm: Kvm,
    #[allow(dead_code)]
    pub vm_fd: VmFd,
    pub vcpu_fd: VcpuFd,
    pub mem_ptr: *mut u8, 
    pub mem_size: usize,
}

impl Drop for Vm {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.mem_ptr as *mut libc::c_void, self.mem_size); }
    }
}

impl Vm {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let kvm = Kvm::new()?;
        let vm_fd = kvm.create_vm()?;

        let mem_ptr = unsafe {
            libc::mmap(ptr::null_mut(), MEM_SIZE, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE, -1, 0) as *mut u8
        };
        if mem_ptr == ptr::null_mut() { return Err("Failed to mmap memory".into()); }

        // [CORE FIX] Memory Split (MMIO Hole 뚫기)
        // 1. 하위 3GB (0 ~ 3GB)
        let mem_region_low = kvm_userspace_memory_region {
            slot: 0, guest_phys_addr: 0, memory_size: MMIO_HOLE_START,
            userspace_addr: mem_ptr as u64, flags: 0,
        };
        // 2. 상위 5GB (4GB ~ 9GB)
        let mem_region_high = kvm_userspace_memory_region {
            slot: 1, guest_phys_addr: 0x100000000, 
            memory_size: (MEM_SIZE as u64 - MMIO_HOLE_START),
            userspace_addr: (mem_ptr as u64 + MMIO_HOLE_START), flags: 0,
        };

        unsafe {
            vm_fd.set_user_memory_region(mem_region_low)?;
            vm_fd.set_user_memory_region(mem_region_high)?;
        }

        vm_fd.set_tss_address(0xfffbd000 as usize)?;
        vm_fd.set_identity_map_address(0xfffbc000)?;
        vm_fd.create_irq_chip()?;
        
        /* 

        // [NEW] Enable Userspace MSR exits to log kernel's system register usage
        if kvm.check_extension(kvm_ioctls::Cap::X86UserSpaceMsr) {
            let mut cap = kvm_bindings::kvm_enable_cap {
                cap: kvm_bindings::KVM_CAP_X86_USER_SPACE_MSR as u32,
                args: [kvm_bindings::KVM_MSR_EXIT_REASON_UNKNOWN as u64, 0, 0, 0],
                ..Default::default()
            };
            vm_fd.enable_cap(&cap)?;
            println!("[VM] Userspace MSR exits enabled.");
        }

        */

        let pit_config = kvm_bindings::kvm_pit_config::default();
        vm_fd.create_pit2(pit_config)?;

        // GSI Routing (PIT->Pin2)
        let mut entries = Vec::new();
        for i in 0..24 {
            let mut io_entry = kvm_irq_routing_entry::default();
            io_entry.gsi = i as u32;
            io_entry.type_ = KVM_IRQ_ROUTING_IRQCHIP;
            let mut io_chip = kvm_bindings::kvm_irq_routing_irqchip::default();
            io_chip.irqchip = 2;
            io_chip.pin = if i == 0 { 2 } else { i as u32 };
            io_entry.u.irqchip = io_chip;
            entries.push(io_entry);
            if i < 16 {
                let mut pic_entry = kvm_irq_routing_entry::default();
                pic_entry.gsi = i as u32;
                pic_entry.type_ = KVM_IRQ_ROUTING_IRQCHIP;
                let mut pic_chip = kvm_bindings::kvm_irq_routing_irqchip::default();
                pic_chip.irqchip = if i < 8 { 0 } else { 1 };
                pic_chip.pin = (i % 8) as u32;
                pic_entry.u.irqchip = pic_chip;
                entries.push(pic_entry);
            }
        }
        let routing = kvm_bindings::KvmIrqRouting::from_entries(&entries)?;
        vm_fd.set_gsi_routing(&routing)?;

        println!("[VM] MMIO Hole (3GB-4GB) created. Memory split into 2 slots.");

        let vcpu_fd = vm_fd.create_vcpu(0)?;

        // [CORE FIX] TSC 주파수 고정 설정
        // 특정 버전의 kvm-ioctls에서 get_tsc_khz가 없을 수 있으므로, 
        // 윈도우 부팅에 권장되는 표준 주파수(예: 3.6GHz = 3600000 KHz)를 시도하거나 
        // 하드웨어 지원 여부를 체크합니다.
        let target_tsc_khz = 3600000; // 3.6 GHz
        if vcpu_fd.set_tsc_khz(target_tsc_khz).is_ok() {
            println!("[VM] TSC Frequency set to: {} KHz", target_tsc_khz);
        }

        let debug_struct = kvm_bindings::kvm_guest_debug {
            control: kvm_bindings::KVM_GUESTDBG_ENABLE | kvm_bindings::KVM_GUESTDBG_USE_SW_BP,
            ..Default::default()
        };
        vcpu_fd.set_guest_debug(&debug_struct)?;

        Ok(Vm { kvm, vm_fd, vcpu_fd, mem_ptr, mem_size: MEM_SIZE })
    }

    pub fn write_memory(&mut self, offset: usize, data: &[u8]) -> Result<(), &'static str> {
        if offset + data.len() > MEM_SIZE { return Err("Memory write out of bounds"); }
        unsafe { ptr::copy_nonoverlapping(data.as_ptr(), self.mem_ptr.add(offset), data.len()); }
        Ok(())
    }

    pub fn read_memory(&self, offset: usize, data: &mut [u8]) -> Result<(), &'static str> {
        if offset + data.len() > MEM_SIZE { return Err("Memory read out of bounds"); }
        unsafe { ptr::copy_nonoverlapping(self.mem_ptr.add(offset), data.as_mut_ptr(), data.len()); }
        Ok(())
    }
}
