# nvdrv-rs
https://github.com/zer0condition/NVDrv - rewritten in rust

## Usage
```rust
let drv = NVDrv::new ();

let cr0 = drv.read_cr(NVControlRegisters::CR0);
println !("CR0: {:#x}", cr0);

let cr2 = drv.read_cr(NVControlRegisters::CR2);
println !("CR2: {:#x}", cr2);

let cr3 = drv.read_cr(NVControlRegisters::CR3);
println !("CR3: {:#x}", cr3);

let cr4 = drv.read_cr(NVControlRegisters::CR4);
println !("CR4: {:#x}", cr4);

unsafe {
  let process_base = drv.get_process_base("explorer.exe");
  println !("Process Base: {:#x}", process_base);

  let dump_size : usize = 0xFFFF;
  let allocation = {
      VirtualAlloc(ptr::null_mut(), dump_size, MEM_COMMIT, PAGE_READWRITE) as *
      mut u8};

            for
              i in 0..(dump_size / 8) {
                let address = allocation.wrapping_add(i * 8);
                let target_address = i * 8;
                drv.read_physical_memory(target_address as u64,
                                         address as * mut c_void, 8);
              }

            NVDrv::write_memory_to_file(r "dump.bin", allocation, dump_size)
                .unwrap();

            VirtualFree(allocation as * mut _, 0, MEM_RELEASE);

            // Disable KVA shadowing
            /*
            let system_cr3 = drv.get_system_cr3();
            println!("System CR3: {:#x}", system_cr3);

            let process_cr3 = drv.get_process_cr3(process_base);
            println!("Process CR3: {:#x}", process_cr3);
            */
}

```
