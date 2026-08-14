use crate::vm::Vm;
use kvm_ioctls::VcpuExit;
use kvm_bindings::{kvm_msr_entry, Msrs};
use std::io::{self, Write, Read};
use crate::debug;
use std::net::{TcpListener, TcpStream};
use gdbstub::stub::GdbStub;
use gdbstub::stub::run_blocking::{BlockingEventLoop, Event as GdbEvent, WaitForStopReasonError};
use gdbstub::stub::{BaseStopReason, DisconnectReason};
use crate::gdb::{VwflTarget, GdbResumeAction};
use gdbstub::common::Tid;
use std::marker::PhantomData;
use gdbstub::conn::{Connection, ConnectionExt};
use std::time::{Instant, Duration};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;

struct ApicState {
    tpr: u32,
    svr: u32,
    lvt_timer: u32,
    init_count: u32,
}

struct HpetState {
    config: u64,
    counter: u64,
}

static mut APIC: ApicState = ApicState {
    tpr: 0,
    svr: 0x1FF, 
    lvt_timer: 0x10000, 
    init_count: 0,
};

static mut HPET: HpetState = HpetState { config: 0, counter: 0 };
static mut START_TIME: Option<Instant> = None;

lazy_static::lazy_static! {
    static ref SERIAL_IN_QUEUE: Arc<Mutex<VecDeque<u8>>> = Arc::new(Mutex::new(VecDeque::new()));
    static ref WINDBG_STREAM: Arc<Mutex<Option<TcpStream>>> = Arc::new(Mutex::new(None));
}

pub fn run(vm: &mut Vm, krnl_entry_v: u64, stack_v: u64, lpb_v: u64) -> Result<(), Box<dyn std::error::Error>> {
    println!("[CPU] Initializing vCPU state...");
    unsafe { START_TIME = Some(Instant::now()); }
    
    start_windbg_server();
    
    setup_long_mode(vm, krnl_entry_v, stack_v, lpb_v)?;
    run_gdb_server(vm)
}


// Windbg 브릿지 서버인데 이게 맞나? 더 case를 나눠서 처리해야 할 수도 있음.(명령어에 따라) 일단은 TCP로 연결만 받아서 SERIAL_IN_QUEUE에 넣는 역할만 수행만 하게 만들어 놓은 것 같음. 아마도?
fn start_windbg_server() {
    thread::spawn(|| {
        let listener = match TcpListener::bind("0.0.0.0:1235") {
            Ok(l) => l,
            Err(_) => return,
        };
        println!("[WINDBG] Bridge ready on 0.0.0.0:1235 (TCP)");
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                println!("[WINDBG] WinDbg connected to bridge.");
                s.set_nonblocking(true).ok();
                let s_clone = s.try_clone().unwrap();
                *WINDBG_STREAM.lock().unwrap() = Some(s);
                
                let mut reader = s_clone;
                thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    loop {
                        // std::io::Read::read를 명시적으로 호출하여 충돌 해결
                        if let Ok(n) = std::io::Read::read(&mut reader, &mut buf) {
                            if n > 0 {
                                let mut queue = SERIAL_IN_QUEUE.lock().unwrap();
                                for i in 0..n { queue.push_back(buf[i]); }
                            } else { break; }
                        }
                        thread::sleep(Duration::from_millis(1));
                    }
                    println!("[WINDBG] WinDbg disconnected.");
                    *WINDBG_STREAM.lock().unwrap() = None;
                });
            }
        }
    });
}

fn run_gdb_server(vm: &mut Vm) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:1234")?;
    println!("\n--- GDB Server Started ---");
    println!("Waiting for GDB connection on 127.0.0.1:1234...");
    
    let (stream, addr) = listener.accept()?;
    println!("GDB Client Connected: {}", addr);
    stream.set_nonblocking(true)?;

    let mut target = VwflTarget { vm, resume_action: None };
    let gdb = GdbStub::new(stream);

    match gdb.run_blocking::<VwflEventLoop<'_>>(&mut target)? {
        DisconnectReason::Disconnect => println!("[GDB] Disconnected."),
        DisconnectReason::Kill => println!("[GDB] Killed by client."),
        _ => println!("[GDB] Stopped."),
    }
    Ok(())
}

struct VwflEventLoop<'a> {
    _phantom: PhantomData<&'a ()>,
}

impl<'a> BlockingEventLoop for VwflEventLoop<'a> {
    type Target = VwflTarget<'a>;
    type Connection = TcpStream;
    type StopReason = BaseStopReason<Tid, u64>;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> Result<GdbEvent<Self::StopReason>, WaitForStopReasonError<&'static str, std::io::Error>> {
        let mut loop_count: u64 = 0;
        let mut last_tick = Instant::now();
        let tick_interval = Duration::from_millis(10); 
        
        loop {
            loop_count += 1;
            
            // ConnectionExt::peek/read를 명시적으로 호출
            match ConnectionExt::peek(conn).map_err(WaitForStopReasonError::Connection)? {
                Some(byte) => {
                    let _ = ConnectionExt::read(conn).map_err(WaitForStopReasonError::Connection)?;
                    return Ok(GdbEvent::IncomingData(byte));
                }
                None => {}
            }

            let now = Instant::now();
            if now.duration_since(last_tick) >= tick_interval {
                update_windows_time(target.vm, loop_count);
                if let Ok(regs) = target.vm.vcpu_fd.get_regs() {
                    if (regs.rflags & 0x200) != 0 {
                        target.vm.vm_fd.set_irq_line(2, true).ok();
                        target.vm.vm_fd.set_irq_line(2, false).ok();
                    }
                }
                last_tick = now;
            }

            {
                let mut kvm_run = target.vm.vcpu_fd.get_kvm_run();
                kvm_run.request_interrupt_window = 1; 
            }

            let exit = target.vm.vcpu_fd.run().map_err(|_| WaitForStopReasonError::Target("KVM Run Error"))?;

            match exit {
                VcpuExit::Debug(_) => return Ok(GdbEvent::TargetStopped(BaseStopReason::DoneStep)),
                VcpuExit::IrqWindowOpen => continue,
                VcpuExit::IoIn(addr, data) => {
                    if addr == 0x3F8 {
                        let mut queue = SERIAL_IN_QUEUE.lock().unwrap();
                        data[0] = queue.pop_front().unwrap_or(0);
                    } else if addr == 0x3FD {
                        let queue = SERIAL_IN_QUEUE.lock().unwrap();
                        data[0] = if queue.is_empty() { 0x60 } else { 0x61 };
                    }
                }
                VcpuExit::IoOut(addr, data) => {
                    let val = data[0];
                    if addr == 0xF9 { 
                        debug::handle_diagnostic_trap(target.vm, val).ok();
                        return Ok(GdbEvent::TargetStopped(BaseStopReason::Signal(gdbstub::common::Signal::SIGTRAP)));
                    }
                    if addr == 0x3F8 {
                        print!("{}", val as char); io::stdout().flush().ok();
                        if let Some(ref mut s) = *WINDBG_STREAM.lock().unwrap() {
                            // std::io::Write::write_all을 명시적으로 호출
                            std::io::Write::write_all(s, &[val]).ok();
                        }
                    }
                }
                VcpuExit::MmioRead(addr, data) => handle_mmio_read(addr, data, loop_count),
                VcpuExit::MmioWrite(addr, data) => handle_mmio_write(addr, data),
                // X86Msr 대신 Msr을 시도하거나, 컴파일러가 제안하는 정확한 이름을 사용해야 함
                // 일단 로그를 위해 Unknown으로 남겨두거나, 버전에 맞는 처리를 수행
                VcpuExit::Hlt => continue,
                VcpuExit::Shutdown => return Ok(GdbEvent::TargetStopped(BaseStopReason::Signal(gdbstub::common::Signal::SIGSEGV))),
                _ => {
                    // MSR 처리가 필요한 경우를 위해 매치 암(match arm)을 좀 더 유연하게 작성
                    return Ok(GdbEvent::TargetStopped(BaseStopReason::Signal(gdbstub::common::Signal::SIGTRAP)));
                }
            }
        }
    }

    fn on_interrupt(_target: &mut Self::Target) -> Result<Option<Self::StopReason>, &'static str> {
        Ok(Some(BaseStopReason::Signal(gdbstub::common::Signal::SIGINT)))
    }
}

fn update_windows_time(vm: &mut Vm, count: u64) {
    let kuser_p = 0x9000000;
    let virtual_time = count.wrapping_mul(10000); 
    let time_bytes = virtual_time.to_le_bytes();
    let high_bytes = (virtual_time >> 32) as u32;
    vm.write_memory((kuser_p + 0x08) as usize, &time_bytes).ok(); 
    vm.write_memory((kuser_p + 0x10) as usize, &high_bytes.to_le_bytes()).ok(); 
    vm.write_memory((kuser_p + 0x14) as usize, &time_bytes).ok(); 
    vm.write_memory((kuser_p + 0x1C) as usize, &high_bytes.to_le_bytes()).ok(); 
}

fn handle_mmio_read(addr: u64, data: &mut [u8], loop_count: u64) {
    if addr >= 0xfee00000 && addr <= 0xfee00fff {
        unsafe {
            let val = match addr & 0xFFF {
                0x20 => 0x0, 0x30 => 0x50014, 0x80 => APIC.tpr, 0xF0 => APIC.svr,
                0x320 => APIC.lvt_timer, 0x380 => APIC.init_count,
                0x390 => if APIC.init_count > 0 { APIC.init_count.wrapping_sub((loop_count & 0xFFFF) as u32) } else { 0x100000 },
                _ => 0,
            };
            let bytes = val.to_le_bytes();
            let len = data.len().min(4);
            data[..len].copy_from_slice(&bytes[..len]);
        }
    } else if addr >= 0xfed00000 && addr <= 0xfed003ff {
        unsafe {
            let val = match addr & 0x3FF {
                0x00 => 0x8086a20100000001u64, 
                0x10 => HPET.config,
                0xF0 => {
                    if let Some(start) = START_TIME {
                        let elapsed = start.elapsed().as_nanos() as u64;
                        elapsed * 1000000 
                    } else {
                        loop_count * 100000
                    }
                },
                _ => 0,
            };
            let len = data.len();
            if len == 8 { data.copy_from_slice(&val.to_le_bytes()); }
            else if len == 4 { data.copy_from_slice(&(val as u32).to_le_bytes()); }
        }
    }
}

fn handle_mmio_write(addr: u64, data: &[u8]) {
    if addr >= 0xfee00000 && addr <= 0xfee00fff {
        unsafe {
            let val = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0;4]));
            match addr & 0xFFF {
                0x80 => APIC.tpr = val, 0xF0 => APIC.svr = val,
                0x320 => APIC.lvt_timer = val, 0x380 => APIC.init_count = val,
                _ => {}
            }
        }
    } else if addr >= 0xfed00000 && addr <= 0xfed003ff {
        unsafe {
            if data.len() >= 4 {
                let val = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0;4]));
                match addr & 0x3FF {
                    0x10 => HPET.config = val as u64,
                    0xF0 => HPET.counter = val as u64,
                    _ => {}
                }
            }
        }
    }
}

fn setup_long_mode(vm: &mut Vm, krnl_entry_v: u64, stack_v: u64, lpb_v: u64) -> Result<(), Box<dyn std::error::Error>> {
    let k_virt_base: u64 = 0xFFFFF80000000000;
    let gdt_pbase: u64 = 0x8000000;
    let tss_pbase: u64 = gdt_pbase + 0x1000;
    let gdt_vbase = k_virt_base + gdt_pbase;
    let tss_vbase = k_virt_base + tss_pbase;
    let kpcr_vaddr: u64 = lpb_v + 0x10000; 
    
    let mut cpuid = vm.kvm.get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)?;
    for entry in cpuid.as_mut_slice() {
        if entry.function == 0x1 { 
            entry.ecx &= !(1 << 31); 
            entry.ecx &= !(1 << 21); 
        }
        if entry.function == 0x40000000 { 
            entry.ebx = 0; entry.ecx = 0; entry.edx = 0; 
        }
    }
    vm.vcpu_fd.set_cpuid2(&cpuid)?;

    let mut gdt: [u64; 32] = [0; 32];
    gdt[1] = 0x00af9a000000ffff; gdt[2] = 0x00af9a000000ffff; gdt[3] = 0x00cf92000000ffff; 
    gdt[4] = 0x00affb000000ffff; gdt[5] = 0x00cff3000000ffff; gdt[10] = 0x00cff3000000ffff; 

    let tss_limit = 104 - 1;
    let tss_low = (tss_vbase & 0xffffff) << 16 | (tss_vbase & 0xff000000) << 32 | 0x0000890000000000 | tss_limit;
    let tss_high = tss_vbase >> 32;
    gdt[8] = tss_low; gdt[9] = tss_high;
    let mut gdt_bytes = Vec::new();
    for entry in &gdt { gdt_bytes.extend_from_slice(&entry.to_le_bytes()); }
    vm.write_memory(gdt_pbase as usize, &gdt_bytes)?;

    let mut tss = [0u8; 104];
    tss[4..12].copy_from_slice(&stack_v.to_le_bytes()); 
    vm.write_memory(tss_pbase as usize, &tss)?;

    let mut sregs = vm.vcpu_fd.get_sregs()?;
    sregs.cr3 = gdt_pbase + 0x100000 + 0x2000;
    sregs.cr4 = (1 << 5) | (1 << 7) | (1 << 9) | (1 << 10) | (1 << 16); 
    sregs.efer = (1 << 0) | (1 << 8) | (1 << 10) | (1 << 11); 
    sregs.cr0 = (1 << 31) | (1 << 0) | (1 << 1) | (1 << 5) | (1 << 16) | (1 << 18);
    sregs.gdt.base = gdt_vbase;
    sregs.gdt.limit = (32 * 8 - 1) as u16;
    sregs.idt.base = k_virt_base + gdt_pbase + 0x20000; 
    sregs.idt.limit = 0x0FFF;

    fn seg_64(selector: u16, is_code: bool) -> kvm_bindings::kvm_segment {
        kvm_bindings::kvm_segment {
            base: 0, limit: 0xffffffff, selector, present: 1,
            type_: if is_code { 11 } else { 3 },
            s: 1, l: if is_code { 1 } else { 0 }, g: 1, db: 0, dpl: 0,
            ..kvm_bindings::kvm_segment::default()
        }
    }
    sregs.cs = seg_64(0x10, true);
    let ds = seg_64(0x18, false);
    sregs.ds = ds; sregs.es = ds; sregs.ss = ds; sregs.gs = ds;
    sregs.gs.base = kpcr_vaddr;
    sregs.tr = kvm_bindings::kvm_segment { base: tss_vbase, limit: tss_limit as u32, selector: 0x40, type_: 9, present: 1, s: 0, g: 0, dpl: 0, ..kvm_bindings::kvm_segment::default() };
    vm.vcpu_fd.set_sregs(&sregs)?;

    let msr_entries = [
        kvm_msr_entry { index: 0xc0000080, data: sregs.efer, ..Default::default() }, 
        kvm_msr_entry { index: 0xc0000101, data: kpcr_vaddr, ..Default::default() }, 
        kvm_msr_entry { index: 0x1b, data: 0xfee00000 | 0x900, ..Default::default() }, 
    ];
    vm.vcpu_fd.set_msrs(&Msrs::from_entries(&msr_entries).unwrap()).ok();

    let mut regs = vm.vcpu_fd.get_regs()?;
    regs.rip = krnl_entry_v;
    regs.rsp = stack_v - 0x100;
    regs.rflags = 0x2;
    regs.rcx = lpb_v;
    regs.rdx = lpb_v; 
    vm.vcpu_fd.set_regs(&regs)?;
    Ok(())
}
