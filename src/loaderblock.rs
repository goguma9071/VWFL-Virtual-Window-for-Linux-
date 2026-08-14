// src/loaderblock.rs
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
use crate::vm::Vm;
use crate::nt_types::*;

/// _TYPE_OF_MEMORY Enum (Windows Kernel Standard)
#[repr(u32)]
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum TYPE_OF_MEMORY {
    LoaderFree = 0,
    LoaderBad = 1,
    LoaderLoadedProgram = 2,
    LoaderFirmwareTemporary = 3,
    LoaderFirmwarePermanent = 4,
    LoaderOsloaderHeap = 5,
    LoaderOsloaderStack = 6,
    LoaderSystemCode = 7,
    LoaderHalCode = 8,
    LoaderBootLdrPage = 9,
    LoaderConsoleInPage = 10,
    LoaderConsoleOutPage = 11,
    LoaderStartupPcrPage = 12,
    LoaderStartupStackPage = 13,
    LoaderStartupDataPage = 14,
    LoaderMemoryData = 15,
    LoaderMemoryTemp = 16,
    LoaderMemorySpecial = 17,
    LoaderMemoryMax = 18,
}

/// _MEMORY_ALLOCATION_DESCRIPTOR - 0x28 bytes
#[repr(C)]
pub struct MEMORY_ALLOCATION_DESCRIPTOR {
    pub ListEntry: LIST_ENTRY,
    pub MemoryType: TYPE_OF_MEMORY,
    pub BasePage: ULONGLONG,
    pub PageCount: ULONGLONG,
}

/// _KLDR_DATA_TABLE_ENTRY - 최신 Windows 10 명세 반영 (0x120 bytes)
#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,                    // 0x0
    pub InMemoryOrderLinks: LIST_ENTRY,                  // 0x10
    pub InInitializationOrderLinks: LIST_ENTRY,          // 0x20
    pub DllBase: PVOID,                                  // 0x30
    pub EntryPoint: PVOID,                               // 0x38
    pub SizeOfImage: ULONG,                              // 0x40
    pub Padding_After_Size: ULONG,                       // 0x44
    pub FullDllName: UNICODE_STRING,                     // 0x48 (0x44 패딩 포함 자동 정렬)
    pub BaseDllName: UNICODE_STRING,                     // 0x58
    pub Flags: ULONG,                                    // 0x68
    pub ObsoleteLoadCount: USHORT,                       // 0x6c
    pub TlsIndex: USHORT,                                // 0x6e
    pub HashLinks: LIST_ENTRY,                           // 0x70
    pub TimeDateStamp: ULONG,                            // 0x80
    pub EntryPointActivationContext: PVOID,              // 0x88 (0x84 패딩 포함)
    pub Lock: PVOID,                                     // 0x90
    pub DdagNode: PVOID,                                 // 0x98
    pub NodeModuleLink: LIST_ENTRY,                      // 0xa0
    pub LoadContext: PVOID,                              // 0xb0
    pub ParentDllBase: PVOID,                            // 0xb8
    pub SwitchBackContext: PVOID,                        // 0xc0
    pub BaseAddressIndexNode: [UCHAR; 24],               // 0xc8
    pub MappingInfoIndexNode: [UCHAR; 24],               // 0xe0
    pub OriginalBase: ULONGLONG,                         // 0xf8
    pub LoadTime: ULONGLONG,                             // 0x100
    pub BaseNameHashValue: ULONG,                        // 0x108
    pub LoadReason: ULONG,                               // 0x10c
    pub ImplicitPathOptions: ULONG,                      // 0x110
    pub ReferenceCount: ULONG,                           // 0x114
    pub DependentLoadFlags: ULONG,                       // 0x118
    pub SigningLevel: UCHAR,                             // 0x11c
    pub Padding_Final: [UCHAR; 3],                       // 0x11d -> 0x120
}

/// _KSPECIAL_REGISTERS - 베르길리우스 명세 반영 (0xf0 bytes)
#[repr(C)]
#[derive(Copy, Clone)]
pub struct KSPECIAL_REGISTERS {
    pub Cr0: ULONGLONG,                                 // 0x0
    pub Cr2: ULONGLONG,                                 // 0x8
    pub Cr3: ULONGLONG,                                 // 0x10
    pub Cr4: ULONGLONG,                                 // 0x18
    pub KernelDr0: ULONGLONG,                           // 0x20
    pub KernelDr1: ULONGLONG,                           // 0x28
    pub KernelDr2: ULONGLONG,                           // 0x30
    pub KernelDr3: ULONGLONG,                           // 0x38
    pub KernelDr6: ULONGLONG,                           // 0x40
    pub KernelDr7: ULONGLONG,                           // 0x48
    pub Gdtr: [UCHAR; 16],                              // 0x50 (KDESCRIPTOR)
    pub Idtr: [UCHAR; 16],                              // 0x60 (KDESCRIPTOR)
    pub Tr: USHORT,                                     // 0x70
    pub Ldtr: USHORT,                                   // 0x72
    pub MxCsr: ULONG,                                   // 0x74
    pub DebugControl: ULONGLONG,                        // 0x78
    pub LastBranchToRip: ULONGLONG,                     // 0x80
    pub LastBranchFromRip: ULONGLONG,                   // 0x88
    pub LastExceptionToRip: ULONGLONG,                  // 0x90
    pub LastExceptionFromRip: ULONGLONG,                // 0x98
    pub Cr8: ULONGLONG,                                 // 0xa0
    pub MsrGsBase: ULONGLONG,                           // 0xa8
    pub MsrGsSwap: ULONGLONG,                           // 0xb0
    pub MsrStar: ULONGLONG,                             // 0xb8
    pub MsrLStar: ULONGLONG,                            // 0xc0
    pub MsrCStar: ULONGLONG,                            // 0xc8
    pub MsrSyscallMask: ULONGLONG,                      // 0xd0
    pub Xcr0: ULONGLONG,                                // 0xd8
    pub MsrFsBase: ULONGLONG,                           // 0xe0
    pub SpecialPadding0: ULONGLONG,                     // 0xe8 -> 0xf0
}

/// _KPROCESSOR_STATE (0x5c0 bytes)
#[repr(C)]
#[derive(Copy, Clone)]
pub struct KPROCESSOR_STATE {
    pub SpecialRegisters: KSPECIAL_REGISTERS,           // 0x0 (0xf0 bytes)
    pub ContextFrame: [UCHAR; 0x4d0],                   // 0xf0 (CONTEXT)
}

/// _KPRCB (Kernel Processor Control Block) - 0x700 bytes
#[repr(C, align(64))]
pub struct KPRCB {
    pub MxCsr: ULONG,                                   // 0x0
    pub LegacyNumber: UCHAR,                            // 0x4
    pub ReservedMustBeZero: UCHAR,                      // 0x5
    pub InterruptRequest: UCHAR,                        // 0x6
    pub IdleHalt: UCHAR,                                // 0x7
    pub CurrentThread: PVOID,                           // 0x8
    pub NextThread: PVOID,                              // 0x10
    pub IdleThread: PVOID,                              // 0x18
    pub NestingLevel: UCHAR,                            // 0x20
    pub ClockOwner: UCHAR,                              // 0x21
    pub PendingTickFlags: UCHAR,                        // 0x22
    pub IdleState: UCHAR,                               // 0x23
    pub Number: ULONG,                                  // 0x24
    pub RspBase: ULONGLONG,                             // 0x28
    pub PrcbLock: ULONGLONG,                            // 0x30
    pub PriorityState: PVOID,                           // 0x38
    pub CpuType: UCHAR,                                 // 0x40
    pub CpuID: UCHAR,                                   // 0x41
    pub CpuStep: USHORT,                                // 0x42
    pub MHz: ULONG,                                     // 0x44
    pub HalReserved: [ULONGLONG; 8],                    // 0x48
    pub MinorVersion: USHORT,                           // 0x88
    pub MajorVersion: USHORT,                           // 0x8a
    pub BuildType: UCHAR,                               // 0x8c
    pub CpuVendor: UCHAR,                               // 0x8d
    pub LegacyCoresPerPhysicalProcessor: UCHAR,         // 0x8e
    pub LegacyLogicalProcessorsPerCore: UCHAR,          // 0x8f
    pub TscFrequency: ULONGLONG,                        // 0x90
    pub CoresPerPhysicalProcessor: ULONG,               // 0x98
    pub LogicalProcessorsPerCore: ULONG,                // 0x9c
    pub PrcbPad04: [ULONGLONG; 4],                      // 0xa0
    pub ParentNode: PVOID,                              // 0xc0
    pub GroupSetMember: ULONGLONG,                      // 0xc8
    pub Group: UCHAR,                                   // 0xd0
    pub GroupIndex: UCHAR,                              // 0xd1
    pub PrcbPad05: [UCHAR; 2],                          // 0xd2
    pub InitialApicId: ULONG,                           // 0xd4
    pub ScbOffset: ULONG,                               // 0xd8
    pub ApicMask: ULONG,                                // 0xdc
    pub AcpiReserved: PVOID,                            // 0xe0
    pub CFlushSize: ULONG,                              // 0xe8
    pub PrcbPad11: [ULONGLONG; 2],                      // 0xf0
    pub ProcessorState: KPROCESSOR_STATE,               // 0x100 (0x5c0 bytes)
    pub ExtendedSupervisorState: PVOID,                 // 0x6c0
    pub ProcessorSignature: ULONG,                      // 0x6c8
    pub ProcessorFlags: ULONG,                          // 0x6cc
    pub PrcbPad12a: ULONGLONG,                          // 0x6d0
    pub PrcbPad12: [ULONGLONG; 3],                      // 0x6d8 -> 0x700
}

/// _KPCR (Kernel Processor Control Region) - 0x178 bytes
#[repr(C, align(16))]
pub struct KPCR {
    pub GdtBase: PVOID,                                 // 0x0
    pub TssBase: PVOID,                                 // 0x8
    pub UserRsp: ULONGLONG,                             // 0x10
    pub SelfPcr: PVOID,                                 // 0x18
    pub CurrentPrcb: PVOID,                             // 0x20
    pub LockArray: PVOID,                               // 0x28
    pub Used_Self: PVOID,                               // 0x30
    pub IdtBase: PVOID,                                 // 0x38
    pub Unused: [ULONGLONG; 2],                         // 0x40
    pub Irql: UCHAR,                                    // 0x50
    pub SecondLevelCacheAssociativity: UCHAR,           // 0x51
    pub ObsoleteNumber: UCHAR,                          // 0x52
    pub Fill0: UCHAR,                                   // 0x53
    pub Unused0: [ULONG; 3],                            // 0x54
    pub MajorVersion: USHORT,                           // 0x60
    pub MinorVersion: USHORT,                           // 0x62
    pub StallScaleFactor: ULONG,                        // 0x64
    pub Unused1: [PVOID; 3],                            // 0x68
    pub KernelReserved: [ULONG; 15],                    // 0x80
    pub SecondLevelCacheSize: ULONG,                    // 0xbc
    pub HalReserved: [ULONG; 16],                       // 0xc0
    pub Unused2: ULONG,                                 // 0x100
    pub Padding_Align: ULONG,                           // 0x104
    pub KdVersionBlock: PVOID,                          // 0x108
    pub Unused3: PVOID,                                 // 0x110
    pub PcrAlign1: [ULONG; 24],                         // 0x118
}

pub struct Kpcr;
impl Kpcr {
    pub fn setup(vm: &mut Vm, vaddr: u64, paddr: u64, gdt_v: u64, idt_v: u64, tss_v: u64, stack_v: u64) -> Result<(), &'static str> {
        let mut kpcr = unsafe { std::mem::zeroed::<KPCR>() };
        kpcr.GdtBase = gdt_v;
        kpcr.TssBase = tss_v;
        kpcr.SelfPcr = vaddr;
        kpcr.CurrentPrcb = vaddr + 0x180;
        kpcr.Used_Self = vaddr;
        kpcr.IdtBase = idt_v;
        kpcr.MajorVersion = 1;
        kpcr.MinorVersion = 1;
        kpcr.StallScaleFactor = 0x00000024;

        let mut prcb = unsafe { std::mem::zeroed::<KPRCB>() };
        prcb.MxCsr = 0x1F80;
        prcb.RspBase = stack_v;
        prcb.MinorVersion = 19041;
        prcb.MajorVersion = 10;
        prcb.TscFrequency = 3600000000;
        prcb.MHz = 3600;
        prcb.ProcessorState.SpecialRegisters.Cr3 = 0x8102000;
        prcb.ProcessorState.SpecialRegisters.Cr0 = 0x80050033;
        prcb.ProcessorState.SpecialRegisters.Cr4 = 0x6f8;
        
        let kpcr_bytes = unsafe { std::slice::from_raw_parts(&kpcr as *const _ as *const u8, std::mem::size_of::<KPCR>()) };
        vm.write_memory(paddr as usize, kpcr_bytes)?;
        
        let prcb_bytes = unsafe { std::slice::from_raw_parts(&prcb as *const _ as *const u8, std::mem::size_of::<KPRCB>()) };
        vm.write_memory((paddr + 0x180) as usize, prcb_bytes)?;
        
        // KPRCB 정밀 수동 보정
        vm.write_memory((paddr + 0x180 + 0xc8) as usize, &1u64.to_le_bytes()).ok(); // GroupSetMember
        vm.write_memory((paddr + 0x180 + 0xd4) as usize, &0u32.to_le_bytes()).ok(); // InitialApicId
        
        Ok(())
    }
}

/// _LOADER_PARAMETER_BLOCK - 0x160 bytes
#[repr(C)]
pub struct LOADER_PARAMETER_BLOCK {
    pub OsMajorVersion: ULONG,                           // 0x0
    pub OsMinorVersion: ULONG,                           // 0x4
    pub Size: ULONG,                                     // 0x8
    pub OsLoaderSecurityVersion: ULONG,                  // 0xc
    pub LoadOrderListHead: LIST_ENTRY,                   // 0x10
    pub MemoryDescriptorListHead: LIST_ENTRY,            // 0x20
    pub BootDriverListHead: LIST_ENTRY,                  // 0x30
    pub EarlyLaunchListHead: LIST_ENTRY,                 // 0x40
    pub CoreDriverListHead: LIST_ENTRY,                  // 0x50
    pub CoreExtensionsDriverListHead: LIST_ENTRY,        // 0x60
    pub TpmCoreDriverListHead: LIST_ENTRY,               // 0x70
    pub KernelStack: ULONGLONG,                          // 0x80
    pub Prcb: ULONGLONG,                                 // 0x88
    pub Process: ULONGLONG,                              // 0x90
    pub Thread: ULONGLONG,                               // 0x98
    pub KernelStackSize: ULONG,                          // 0xa0
    pub RegistryLength: ULONG,                           // 0xa4
    pub RegistryBase: PVOID,                             // 0xa8
    pub ConfigurationRoot: PVOID,                        // 0xb0
    pub ArcBootDeviceName: PVOID,                        // 0xb8
    pub ArcHalDeviceName: PVOID,                         // 0xc0
    pub NtBootPathName: PVOID,                           // 0xc8
    pub NtHalPathName: PVOID,                            // 0xd0
    pub LoadOptions: PVOID,                              // 0xd8
    pub NlsData: PVOID,                                  // 0xe0
    pub ArcDiskInformation: PVOID,                       // 0xe8
    pub Extension: PVOID,                                // 0xf0
    pub u: [UCHAR; 16],                                  // 0xf8
    pub FirmwareInformation: [UCHAR; 64],                // 0x108
    pub OsBootstatPathName: PVOID,                       // 0x148
    pub ArcOSDataDeviceName: PVOID,                      // 0x150
    pub ArcWindowsSysPartName: PVOID,                    // 0x158
}

pub struct LoaderParameterBlock;
impl LoaderParameterBlock {
    pub fn setup(vm: &mut Vm, lpb_v: u64, lpb_p: u64, prcb_v: u64, stack_v: u64, stack_size: u32, registry_v: u64, registry_size: u32, nls_v: u64) -> Result<(), &'static str> {
        let mut lpb = unsafe { std::mem::zeroed::<LOADER_PARAMETER_BLOCK>() };
        lpb.OsMajorVersion = 10;
        lpb.Size = 0x160;
        lpb.KernelStack = stack_v;
        lpb.Prcb = prcb_v;

        // [CORE FIX] prcb_v는 kpcr + 0x180이므로, kpcr 베이스를 먼저 구함
        let kpcr_v = prcb_v - 0x180;
        lpb.Process = kpcr_v + 0x6000;
        lpb.Thread = kpcr_v + 0x5000;

        lpb.KernelStackSize = stack_size;
        lpb.RegistryLength = registry_size;
        lpb.RegistryBase = registry_v;
        lpb.NlsData = nls_v;
        lpb.Extension = lpb_v + 0x8000;
        
        let options_str = ""; //"/DEBUG /DEBUGPORT=COM1 /BAUDRATE=115200 /EMS"; 
        let mut options_bytes = options_str.as_bytes().to_vec();
        options_bytes.push(0);
        vm.write_memory((lpb_p + 0xC000) as usize, &options_bytes).ok();
        lpb.LoadOptions = lpb_v + 0xC000;

        let bytes = unsafe { std::slice::from_raw_parts(&lpb as *const _ as *const u8, 0x160) };
        vm.write_memory(lpb_p as usize, bytes)?;
        Ok(())
    }
    pub fn add_memory(vm: &mut Vm, _lpb_v: u64, _lpb_p: u64, _entry_v: u64, entry_p: u64, base_addr: u64, size: u64, mem_type: u32) -> Result<(), &'static str> {
        let mut desc = unsafe { std::mem::zeroed::<MEMORY_ALLOCATION_DESCRIPTOR>() };
        desc.MemoryType = unsafe { std::mem::transmute(mem_type) };
        desc.BasePage = base_addr >> 12;
        desc.PageCount = size >> 12;
        let bytes = unsafe { std::slice::from_raw_parts(&desc as *const _ as *const u8, 0x28) };
        vm.write_memory(entry_p as usize, bytes)?;
        Ok(())
    }
}

/// _LOADER_PARAMETER_EXTENSION - 0xe38 bytes
#[repr(C)]
pub struct LOADER_PARAMETER_EXTENSION {
    pub Size: ULONG,                                    // 0x0
    pub Profile: [UCHAR; 0x14],                         // 0x4
    pub EmInfFileImage: PVOID,                          // 0x18
    pub EmInfFileSize: ULONG,                           // 0x20
    pub TriageDumpBlock: PVOID,                         // 0x28
    pub HeadlessLoaderBlock: PVOID,                     // 0x30
    pub SMBiosEPSHeader: PVOID,                         // 0x38
    pub DrvDBImage: PVOID,                              // 0x40
    pub DrvDBSize: ULONG,                               // 0x48
    pub DrvDBPatchImage: PVOID,                         // 0x50
    pub DrvDBPatchSize: ULONG,                          // 0x58
    pub NetworkLoaderBlock: PVOID,                      // 0x60
    pub FirmwareDescriptorListHead: LIST_ENTRY,         // 0x68
    pub AcpiTable: PVOID,                               // 0x78
    pub AcpiTableSize: ULONG,                           // 0x80
    pub Bitfields: ULONG,                               // 0x84
    pub LoaderPerformanceData: [UCHAR; 0x60],           // 0x88
    pub BootApplicationPersistentData: LIST_ENTRY,      // 0xe8
    pub Padding1: [UCHAR; 0x8D0],                       // 0xF8 -> 0x9C8
    pub ProcessorCounterFrequency: ULONGLONG,           // 0x9c0
    pub HypervisorExtension: [UCHAR; 0x40],             // 0x9c8
    pub HardwareConfigurationId: [UCHAR; 16],           // 0xa08
    pub HalExtensionModuleList: LIST_ENTRY,             // 0xa18
    pub SystemTime: ULONGLONG,                          // 0xa28
    pub TimeStampAtSystemTimeRead: ULONGLONG,           // 0xa30
    pub BootFlags: ULONGLONG,                           // 0xa38
    pub InternalBootFlags: ULONGLONG,                   // 0xa40
    pub WfsFPData: PVOID,                               // 0xa48
    pub WfsFPDataSize: ULONG,                           // 0xa50
    pub BugcheckParameters: [UCHAR; 0x28],              // 0xa58
    pub ApiSetSchema: PVOID,                            // 0xa80
    pub ApiSetSchemaSize: ULONG,                        // 0xa88
    pub ApiSetSchemaExtensions: LIST_ENTRY,             // 0xa90
    pub PaddingFinal: [UCHAR; 0x390],                   // 0xaa0 -> 0xe30
    pub MajorRelease: ULONG,                            // 0xb88
    pub MinorRelease: ULONG,                            // 0xb8c
}

pub struct LoaderParameterExtension;
impl LoaderParameterExtension {
    pub const OFFSET_IN_LPB: u64 = 0x8000;
    pub fn setup(vm: &mut Vm, ext_p: u64, ext_v: u64) -> Result<(), &'static str> {
        let mut ext = unsafe { std::mem::zeroed::<LOADER_PARAMETER_EXTENSION>() };
        ext.Size = 0xE38;
        ext.Bitfields = 0x4000; 
        ext.MajorRelease = 10;
        ext.MinorRelease = 0;
        let list_head_v = ext_v + 0xA18;
        ext.HalExtensionModuleList.Flink = list_head_v;
        ext.HalExtensionModuleList.Blink = list_head_v;
        let bytes = unsafe { std::slice::from_raw_parts(&ext as *const _ as *const u8, 0xE38) };
        vm.write_memory(ext_p as usize, bytes)?;
        Ok(())
    }
    pub fn set_acpi(vm: &mut Vm, ext_p: u64, rsdp_v: u64) -> Result<(), &'static str> {
        vm.write_memory((ext_p + 0x78) as usize, &rsdp_v.to_le_bytes())?;
        vm.write_memory((ext_p + 0x80) as usize, &36u32.to_le_bytes())?;
        Ok(())
    }
    pub fn set_apiset(vm: &mut Vm, ext_p: u64, apiset_v: u64, size: u32) -> Result<(), &'static str> {
        vm.write_memory((ext_p + 0xA80) as usize, &apiset_v.to_le_bytes())?;
        vm.write_memory((ext_p + 0xA88) as usize, &size.to_le_bytes())?;
        Ok(())
    }
}

pub struct LdrDataTableEntry;
impl LdrDataTableEntry {
    pub fn add_module(vm: &mut Vm, _entry_v: u64, entry_p: u64, img_base: u64, entry_point: u64, size: u32, name: &str) -> Result<(), &'static str> {
        let mut ldr = unsafe { std::mem::zeroed::<LDR_DATA_TABLE_ENTRY>() };
        ldr.DllBase = img_base;
        ldr.EntryPoint = entry_point;
        ldr.SizeOfImage = size;
        ldr.Flags = 0x40004; 
        ldr.ObsoleteLoadCount = 1;
        let name_v = _entry_v + 0x150;
        let mut name_u16: Vec<u8> = Vec::new();
        for c in name.encode_utf16() { name_u16.extend_from_slice(&c.to_le_bytes()); }
        let len = name_u16.len() as u16;
        ldr.FullDllName.Length = len;
        ldr.FullDllName.MaximumLength = len + 2;
        ldr.FullDllName.Buffer = name_v;
        ldr.BaseDllName.Length = len;
        ldr.BaseDllName.MaximumLength = len + 2;
        ldr.BaseDllName.Buffer = name_v;
        let bytes = unsafe { std::slice::from_raw_parts(&ldr as *const _ as *const u8, 0x120) };
        vm.write_memory(entry_p as usize, bytes)?;
        vm.write_memory((entry_p + 0x150) as usize, &name_u16)?;
        Ok(())
    }
}
