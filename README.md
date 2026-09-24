# vashMem

Windows library for reading, writing, and scanning another process's memory from Go.

```
go get github.com/bytearr/vashMem
```

Import the package as `MemoryScanning`. The caller needs a PID from `GetPid`, or a handle from `GetProcessHandle` opened with `PROCESS_VM_READ`. Writes also need `PROCESS_VM_WRITE` and `PROCESS_VM_OPERATION`.

Pointer walks use the target process width: 4 bytes when that process is 32-bit, 8 when it is 64-bit. The call stays the same. `IsTarget64bit` still reports this process, not the target.

## Read and write

`ReadMemory` reads an integer of the given size. `ReadMemoryStr` reads bytes until a 0, and stops with an error after 4096 bytes.

`WriteProcessMemory` writes one float32. `WriteBytes` writes a hex pattern such as `"90 90"`. `WriteRaw` writes a byte slice. With more than one offset, each offset except the last is a pointer followed inside the target process. The last offset is added. A single offset is only added.

`GetAddress` walks a `+` separated offset string the same way, after reading the pointer at `Base+Address`.

## Scan

`ProcessPatternScan` walks committed memory from `startAddress` to `endAddress`. `endAddress` 0 means the user-space range. `??` is a wildcard, for example `"48 8B ?? 00"`.

`ModulePatternScan` limits that walk to one module. `GetModuleInfo` returns that module's base and size. `GetPointerStatic` remembers a pattern until the bytes at the cached address change.

A scan result of 0 or below means the pattern was not found.
