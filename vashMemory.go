package MemoryScanning

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	user32DLL              = syscall.NewLazyDLL("user32.dll")
	enumWindowsProc        = user32DLL.NewProc("EnumWindows")
	getWindowThreadProcess = user32DLL.NewProc("GetWindowThreadProcessId")
	isWindowVisibleProc    = user32DLL.NewProc("IsWindowVisible")
	openProcessProc        = kernel32.NewProc("OpenProcess")
	getWindowLong          = user32DLL.NewProc("GetWindowLongA")
	getWindowLongPtr       = user32DLL.NewProc("GetWindowLongPtrA")
	readProcessMemory      = kernel32.NewProc("ReadProcessMemory")
	writeProcessMemory     = kernel32.NewProc("WriteProcessMemory")
	openProcess            = kernel32.NewProc("OpenProcess")
	closeHandle            = kernel32.NewProc("CloseHandle")
	isWow64ProcessProc     = kernel32.NewProc("IsWow64Process")
	aobCache               []AobCache
	aobMu                  sync.Mutex
)

const (
	PROCESS_ALL_ACCESS                = 0x1F0FFF
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_VM_READ                   = 0x0010
	LIST_MODULES_ALL                  = 0x03
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_VM_WRITE                  = 0x0020
	PROCESS_VM_OPERATION              = 0x0008
	PROCESS_QUERY_INFO                = 0x0400
	GWL_HINSTANCE                     = int32(-6)
	maxStringRead                     = 4096
)

type AobCache struct {
	aobPattern string
	address    uintptr
	expected   string
}

type ModuleInfo struct {
	Name        string
	FileName    string
	lpBaseOfDll uintptr
	SizeOfImage int
	EntryPoint  uintptr
}

type MemoryInfo struct {
	BaseAddress uintptr
	RegionSize  uintptr
	State       uint32
	Protect     uint32
}

func GetPointerDynamic(pHandle, base *uintptr, aobScan *string, offset int64, pid *uint32, size int) uintptr {
	if size == 0 {
		size = 4
	}
	pattern, err := HexStringToPattern(*aobScan)
	if err != nil {
		fmt.Println("could not convert aobScan to converted AOB", aobScan, err)
		return 0
	}
	found := ProcessPatternScan(pHandle, 0, 0, pattern...)
	if found <= 0 {
		fmt.Println("address location of pattern scan invalid")
		return 0
	}
	memRead, err := ReadMemory(uintptr(found+offset), int(*pid), size)
	if err != nil {
		fmt.Println("address location of pattern scan invalid: ", err)
		return 0
	}
	return uintptr(memRead) - *base
}

func GetModulePatternStatic(pid uint32, hProcess *uintptr, moduleName string, aobScan string, size int) (uintptr, error) {
	if size == 0 {
		size = 4
	}
	buf := make([]byte, 32)
	pattern, err := HexStringToPattern(aobScan)
	if err != nil {
		fmt.Printf("could not convert aobScan (%v) to converted AOB(%v)\n", aobScan, err)
		return 0, err
	}

	addrLocation, err := ModulePatternScan(pid, hProcess, moduleName, pattern...)
	if err != nil {
		fmt.Printf("address location of module pattern scan invalid: %v; %v\n", err, pattern)
		return 0, err
	}
	if addrLocation == 0 {
		return 0, fmt.Errorf("could not find pattern in module")
	}
	relativeLocation := uintptr(addrLocation)

	res := ReadRaw(hProcess, &relativeLocation, buf)
	if !res {
		//fmt.Println("could not read memory at relative location")
		return 0, fmt.Errorf("could not read memory at relative location")
	}
	return relativeLocation, nil
}

func GetPointerStatic(pHandle, base *uintptr, aobScan *string, offset int64, pid *uint32, size int) uintptr {
	if size == 0 {
		size = 4
	}
	prebuf := make([]byte, 32)
	buf := make([]byte, 32)
	aobMu.Lock()
	cached := append([]AobCache(nil), aobCache...)
	aobMu.Unlock()
	for _, item := range cached {
		if item.aobPattern != *aobScan || item.address == 0 {
			continue
		}
		addr := item.address
		ReadRaw(pHandle, &addr, prebuf)
		if item.expected == ByteArrayToString(prebuf) {
			return addr
		}
	}
	pattern, err := HexStringToPattern(*aobScan)
	if err != nil {
		fmt.Println("could not convert aobScan to converted AOB", aobScan, err)
		return 0
	}
	found := ProcessPatternScan(pHandle, 0, 0, pattern...)
	if found <= 0 {
		fmt.Println("address location of pattern scan invalid")
		return 0
	}
	memRead, err := ReadMemory(uintptr(found+offset), int(*pid), size)
	if err != nil {
		fmt.Println("address location of pattern scan invalid", err)
		return 0
	}
	relativeLocation := uintptr(memRead) - *base

	ReadRaw(pHandle, &relativeLocation, buf)
	aobMu.Lock()
	aobCache = append(aobCache, AobCache{*aobScan, relativeLocation, ByteArrayToString(buf)})
	aobMu.Unlock()
	return relativeLocation
}
func Int64ToHex(num int64) string {
	hexString := strconv.FormatInt(num, 16)
	return hexString
}
func UintptrToHex(ptr uintptr) string {
	hexString := strconv.FormatUint(uint64(ptr), 16)
	return hexString
}

func ByteArrayToString(arr []byte) string {
	str := ""
	for _, val := range arr {
		str += strconv.Itoa(int(val)) + " "
	}
	return strings.TrimSpace(str)
}

func GetInstanceHandle(handle uintptr) (uintptr, error) {
	var proc *syscall.LazyProc
	var index int32

	if unsafe.Sizeof(uintptr(0)) == 4 {
		proc = getWindowLong
		index = GWL_HINSTANCE
	} else {
		proc = getWindowLongPtr
		index = GWL_HINSTANCE
	}

	r1, _, err := proc.Call(handle, uintptr(index))
	if err != syscall.Errno(0) {
		return 0, fmt.Errorf("failed to get instance handle: %v", err)
	}

	return r1, nil
}

func GetPid(exeName string) uint32 {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	for err := windows.Process32First(snapshot, &pe); err == nil; err = windows.Process32Next(snapshot, &pe) {
		if strings.ToLower(windows.UTF16ToString(pe.ExeFile[:])) == strings.ToLower(exeName) {
			return pe.ProcessID
		}
	}
	return 0
}

func GetHwndByProcessID(pid uint32) (uintptr, error) {
	var hwnd uintptr
	found := false

	callback := syscall.NewCallback(func(window uintptr, lParam uintptr) uintptr {
		var processID uint32
		getWindowThreadProcess.Call(window, uintptr(unsafe.Pointer(&processID)))

		if processID == pid {
			isVisible, _, _ := isWindowVisibleProc.Call(window)
			if isVisible != 0 {
				hwnd = window
				found = true
				return 0
			}
		}
		return 1
	})

	ret, _, callErr := enumWindowsProc.Call(callback, 0)

	if ret == 0 && !found {
		return 0, fmt.Errorf("failed to enumerate windows: %v", callErr)
	}

	if hwnd == 0 {
		return 0, fmt.Errorf("no window found for process ID %d", pid)
	}

	return hwnd, nil
}

func IntToHex(num int) string {
	hexStr := fmt.Sprintf("0x%x", num)
	return hexStr
}

func ReadMemory(MADDRESS uintptr, pid int, size int) (uint64, error) {
	if size == 0 {
		size = 4
	}

	buffer := make([]byte, size)

	handle, _, err := openProcessProc.Call(uintptr(PROCESS_VM_READ), 0, uintptr(pid))
	if handle == 0 {
		return 0, fmt.Errorf("failed to open process: %v", err)
	}

	var totalBytesRead uintptr
	for totalBytesRead < uintptr(size) {
		var bytesRead uintptr
		r1, _, err := readProcessMemory.Call(handle, MADDRESS+totalBytesRead, uintptr(unsafe.Pointer(&buffer[totalBytesRead])), uintptr(size-int(totalBytesRead)), uintptr(unsafe.Pointer(&bytesRead)))
		if r1 == 0 {
			syscall.CloseHandle(syscall.Handle(handle))
			return 0, fmt.Errorf("failed to read memory: %v", err)
		}
		totalBytesRead += bytesRead
		if bytesRead == 0 {
			syscall.CloseHandle(syscall.Handle(handle))
			return 0, fmt.Errorf("only part of the memory was read: expected %d bytes, but read %d bytes", size, totalBytesRead)
		}
	}

	var result uint64
	for i := 0; i < size; i++ {
		result |= uint64(buffer[i]) << (8 * i)
	}
	syscall.CloseHandle(syscall.Handle(handle))
	return result, nil
}
func ReadMemoryStr(address uintptr, pid int) (string, error) {
	handle, _, err := openProcessProc.Call(uintptr(PROCESS_VM_READ), 0, uintptr(pid))
	if handle == 0 {
		return "", fmt.Errorf("failed to open process: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	var testStr strings.Builder
	var output byte
	for i := 0; i < maxStringRead; i++ {
		var bytesRead uintptr
		r1, _, readErr := readProcessMemory.Call(
			handle,
			address,
			uintptr(unsafe.Pointer(&output)),
			1,
			uintptr(unsafe.Pointer(&bytesRead)),
		)
		if r1 == 0 || bytesRead == 0 {
			return "", fmt.Errorf("failed to read memory: %v", readErr)
		}
		if output == 0 {
			return testStr.String(), nil
		}
		testStr.WriteByte(output)
		address++
	}
	return "", fmt.Errorf("string longer than %d bytes", maxStringRead)
}

func WriteProcessMemory(pid uint32, address uintptr, valueToWrite float32, size uint32) error {

	// Open the process with all access
	processHandle, _, err := openProcess.Call(PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION, 0, uintptr(pid))
	if processHandle == 0 {
		return fmt.Errorf("failed to open process: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(processHandle))
	// Convert the float value to bytes
	valueBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueBytes, math.Float32bits(valueToWrite))

	// Write the value to the process memory
	var bytesWritten uintptr
	ret, _, err := writeProcessMemory.Call(processHandle, address, uintptr(unsafe.Pointer(&valueBytes[0])), uintptr(len(valueBytes)), uintptr(unsafe.Pointer(&bytesWritten)))
	if ret == 0 {
		return fmt.Errorf("failed to write process memory: %v", err)
	}

	return nil
}

func FloatToHex(f float64) string {
	bits := math.Float64bits(f)
	return fmt.Sprintf("0x%X", bits)
}
func GetAddress(PID int, Base uintptr, Address uintptr, Offset string) (uintptr, error) {
	PointerBase := Base + Address

	if Offset == "" {
		return PointerBase, nil
	}
	width := pointerSizeForPid(PID)
	y, err := ReadMemory(PointerBase, PID, width)
	if err != nil {
		return 0, err
	}

	offsetSplit := strings.Split(Offset, "+")
	offsetCount := len(offsetSplit)

	for i := 0; i < offsetCount; i++ {
		offsetValue := offsetSplit[i]
		offset, err := strconv.ParseUint(offsetValue, 0, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse offset: %v", err)
		}
		if i == offsetCount-1 {
			finalAddress := uintptr(y + offset)
			return finalAddress, nil
		} else {
			newAddress := y + offset
			y, err = ReadMemory(uintptr(newAddress), PID, width)
			if err != nil {
				return 0, err
			}
		}
	}

	return 0, nil
}

func HexToFloat(d uint32) float32 {
	return math.Float32frombits(d)
}

func HexToFloatBig(x uint32) float32 {
	return math.Float32frombits(x)
}
func Float32ToFloat64(f32 float32) float64 {
	return float64(f32)
}

func Float64ToFloat32(f64 float64) float32 {
	return float32(f64)
}

func HexToFloat64(d uint64) float64 {
	return math.Float64frombits(d)
}

func Float64ToHex(f float64) string {
	return fmt.Sprintf("0x%X", math.Float64bits(f))
}

func Float64ToUint64(f float64) uint64 {
	//fmt.Println(math.Float64bits(f))
	return math.Float64bits(f)
}

func Float64ToUint32(f float64) uint32 {
	return uint32(math.Float32bits(Float64ToFloat32(f)))
}

func IntToHexOld(value int) string {
	var hexStr string

	for i := 7; i >= 0; i-- {
		n := (value >> (i * 4)) & 0xf

		if n > 9 {
			hexStr += string(rune('A' + n - 10))
		} else {
			hexStr += fmt.Sprintf("%X", n)
		}
	}

	return "0x" + hexStr
}
func ProcessPatternScan(hProcess *uintptr, startAddress uintptr, endAddress uintptr, aobPattern ...string) int64 {
	const (
		MEM_COMMIT    = 0x1000
		MEM_MAPPED    = 0x40000
		MEM_PRIVATE   = 0x20000
		PAGE_NOACCESS = 0x01
		PAGE_GUARD    = 0x100
	)

	address := startAddress

	if endAddress == 0 {
		if unsafe.Sizeof(uintptr(0)) == 8 {
			endAddress = 0x7FFFFFFFFFF
		} else {
			endAddress = 0xFFFFFFFF
		}
	}

	patternMask, aobBuffer, patternSize := GetNeedleFromAOBPattern(&aobPattern)
	if patternSize <= 0 {
		return -10
	}

	for address <= endAddress {
		var memInfo MemoryInfo

		if !VirtualQueryEx(*hProcess, address, &memInfo) {
			fmt.Printf("VirtualQueryEx failed for address: 0x%X\n", address)
			return -1
		}

		span, next, ok := regionSpan(address, memInfo)
		if !ok {
			next = address + 0x1000
			if memInfo.BaseAddress > address {
				next = memInfo.BaseAddress
			}
			if next <= address {
				return 0
			}
			address = next
			continue
		}

		if memInfo.State == MEM_COMMIT &&
			(memInfo.Protect&(PAGE_NOACCESS|PAGE_GUARD) == 0) &&
			span >= uintptr(patternSize) {

			result := PatternScan(hProcess, &address, &span, patternMask, &aobBuffer)
			if result > 0 {
				return result
			}
		}

		address = next
	}

	return 0
}

func GetNeedleFromAOBPattern(aobPattern *[]string) (string, []byte, int) {
	var patternMask string
	var needleBuffer []byte

	for _, v := range *aobPattern {
		if v == "??" {
			patternMask += "?"
			needleBuffer = append(needleBuffer, 0)
		} else {
			patternMask += "x"
			bytes, err := HexStringToBytes(v)
			if err != nil {
				fmt.Println("error in needle aob", err)
				return "", nil, -1
			}
			needleBuffer = append(needleBuffer, bytes...)
		}
	}
	return patternMask, needleBuffer, len(needleBuffer)
}
func HexStringToBytes(hexString string) ([]byte, error) {
	if strings.HasPrefix(hexString, "0x") {
		hexString = hexString[2:]
	}

	bytes := make([]byte, len(hexString)/2)
	for i := 0; i < len(hexString); i += 2 {
		val, err := strconv.ParseInt(hexString[i:i+2], 16, 64)
		if err != nil {
			//fmt.Println(hexString[i:i+2], hexString)
			return nil, fmt.Errorf("error parsing hex string '%s': %w", hexString[i:i+2], err)
		}
		bytes[i/2] = byte(val)
	}

	return bytes, nil
}

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

var kernel32a = syscall.MustLoadDLL("kernel32.dll")
var VirtualQueryExProc = kernel32a.MustFindProc("VirtualQueryEx")

func VirtualQueryEx(hProcess uintptr, address uintptr, memInfo *MemoryInfo) bool {
	var mbi MEMORY_BASIC_INFORMATION

	_, _, err := VirtualQueryExProc.Call(
		hProcess,
		address,
		uintptr(unsafe.Pointer(&mbi)),
		unsafe.Sizeof(mbi),
	)

	if err != nil && err.(syscall.Errno) != 0 {
		return false
	}

	memInfo.BaseAddress = mbi.BaseAddress
	memInfo.RegionSize = mbi.RegionSize
	memInfo.State = mbi.State
	memInfo.Protect = mbi.Protect

	return true
}

func PatternScan(hProcess *uintptr, address *uintptr, sizeOfRegionBytes *uintptr, patternMask string, needleBuffer *[]byte) int64 {
	buffer := make([]byte, *sizeOfRegionBytes)
	if !ReadRaw(hProcess, address, buffer) {
		return -1
	}

	offset, found := BufferScanForMaskedPattern(&buffer, patternMask, needleBuffer)
	if found {
		return int64(*address + uintptr(offset))
	}
	return 0
}

func BufferScanForMaskedPattern(haystack *[]byte, patternMask string, needle *[]byte) (int, bool) {
	needleSize := len(*needle)

	for i := 0; i <= len(*haystack)-needleSize; i++ {
		match := true
		for j := 0; j < needleSize; j++ {
			if patternMask[j] == 'x' && (*haystack)[i+j] != (*needle)[j] {
				match = false
				break
			}
		}

		if match {
			return i, true
		}
	}

	return -1, false
}

var readProcessMemoryProc = kernel32a.MustFindProc("ReadProcessMemory")

func ReadRaw(hProcess *uintptr, address *uintptr, buffer []byte, offsets ...uintptr) bool {
	targetAddress, addrErr := GetAddressFromOffsets(*hProcess, *address, offsets...)
	if addrErr != nil {
		return false
	}

	var numberOfBytesRead uint32

	res, _, err := readProcessMemoryProc.Call(
		*hProcess,
		targetAddress,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&numberOfBytesRead)),
	)

	if res == 0 {
		if err != syscall.Errno(0) {
			fmt.Printf("Error reading memory: %v\n", err)
		} else if numberOfBytesRead != uint32(len(buffer)) {
			fmt.Printf("Only partial memory was read: expected %d bytes, but read %d bytes\n", len(buffer), numberOfBytesRead)
		}
		return false
	}

	return true
}

func GetAddressFromOffsets(hProcess uintptr, address uintptr, offsets ...uintptr) (uintptr, error) {
	if len(offsets) == 0 {
		return address, nil
	}
	current := address
	for i := 0; i < len(offsets)-1; i++ {
		ptr, err := readPointer(hProcess, current)
		if err != nil {
			return 0, err
		}
		current = ptr + offsets[i]
	}
	return current + offsets[len(offsets)-1], nil
}

func Pointer(hProcess uintptr, address uintptr, offsets ...uintptr) (uintptr, error) {
	current := address
	for _, offset := range offsets {
		ptr, err := readPointer(hProcess, current)
		if err != nil {
			return 0, err
		}
		current = ptr + offset
	}
	return current, nil
}
func GetProcessHandle(pid uint32) uintptr {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	openProcessProc := kernel32.MustFindProc("OpenProcess")

	const (
		PROCESS_QUERY_INFORMATION = 0x0400
		PROCESS_VM_READ           = 0x0010
	)

	handle, _, _ := openProcessProc.Call(
		PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,
		uintptr(0),
		uintptr(pid),
	)

	if handle == 0 {
		return 0
	}

	return handle
}

func HexStringToPattern(hexString string) ([]string, error) {
	var aobPattern []string

	hexString = strings.ReplaceAll(hexString, " ", "")
	hexString = strings.ReplaceAll(hexString, "0x", "")

	wildcardCount := strings.Count(hexString, "?")

	if len(hexString) == 0 {
		return nil, fmt.Errorf("empty hex string")
	}

	if ContainsInvalidChars(hexString) {
		return nil, fmt.Errorf("hex string contains invalid characters")
	}

	if wildcardCount%2 != 0 {
		return nil, fmt.Errorf("odd number of wildcard characters")
	}

	if len(hexString)%2 != 0 {
		return nil, fmt.Errorf("hex string length is not even")
	}

	for i := 0; i < len(hexString); i += 2 {
		hexByte := hexString[i : i+2]
		if hexByte == "??" {
			aobPattern = append(aobPattern, "??")
		} else {
			aobPattern = append(aobPattern, hexByte)
		}
	}

	return aobPattern, nil
}

func ContainsInvalidChars(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') && c != '?' {
			return true
		}
	}
	return false
}

func SplitPath(path string) (string, string) {
	idx := strings.LastIndexByte(path, '\\')
	if idx == -1 {
		return "", path
	}
	return path[:idx], path[idx+1:]
}

func IsTarget64bit() (bool, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	isWow64ProcessProc := kernel32.NewProc("IsWow64Process")

	var isWow64 bool
	currentProcess, err := syscall.GetCurrentProcess()
	if err != nil {
		return false, err
	}

	r1, _, callErr := isWow64ProcessProc.Call(
		uintptr(currentProcess),
		uintptr(unsafe.Pointer(&isWow64)),
	)
	if r1 == 0 {
		return false, callErr
	}

	return !isWow64, nil
}
func ModulePatternScan(pid uint32, hProcess *uintptr, moduleName string, aobPattern ...string) (int64, error) {
	const (
		MEM_COMMIT    = 0x1000
		MEM_MAPPED    = 0x40000
		MEM_PRIVATE   = 0x20000
		PAGE_NOACCESS = 0x01
		PAGE_GUARD    = 0x100
	)

	var moduleInfo ModuleInfo
	var patternMask string
	var needleBuffer []byte
	var patternSize int
	if moduleName != "" {
		moduleInfo, _ = GetModuleInfo(pid, moduleName)
		//fmt.Println(moduleInfo)
	} else {
		moduleInfo.lpBaseOfDll = 0
		moduleInfo.SizeOfImage = 0x7FFFFFFF
	}

	patternMask, needleBuffer, patternSize = GetNeedleFromAOBPattern(&aobPattern)
	if patternSize <= 0 {
		return 0, fmt.Errorf("invalid pattern size")
	}

	for address := moduleInfo.lpBaseOfDll; address < moduleInfo.lpBaseOfDll+uintptr(moduleInfo.SizeOfImage); {
		var memInfo MemoryInfo

		if !VirtualQueryEx(*hProcess, address, &memInfo) {
			//fmt.Printf("VirtualQueryEx failed for address: 0x%X\n", address)
			return 0, fmt.Errorf("VirtualQueryEx failed for address: 0x%X", address)
		}

		span, next, ok := regionSpan(address, memInfo)
		if !ok {
			return 0, fmt.Errorf("pattern not found")
		}

		if memInfo.State == MEM_COMMIT &&
			(memInfo.Protect&(PAGE_NOACCESS|PAGE_GUARD) == 0) &&
			span >= uintptr(patternSize) {

			result := PatternScan(hProcess, &address, &span, patternMask, &needleBuffer)

			if result > 0 {
				return result, nil
			}
		}

		address = next
	}
	return 0, fmt.Errorf("pattern not found")
}

func pointerSize() int {
	return int(unsafe.Sizeof(uintptr(0)))
}

func regionSpan(address uintptr, info MemoryInfo) (span uintptr, next uintptr, ok bool) {
	if info.RegionSize == 0 {
		return 0, 0, false
	}
	end := info.BaseAddress + info.RegionSize
	if end <= address {
		return 0, 0, false
	}
	return end - address, end, true
}

func targetPointerSize(handle uintptr) int {
	var wow64 int32
	r1, _, _ := isWow64ProcessProc.Call(handle, uintptr(unsafe.Pointer(&wow64)))
	if r1 != 0 && wow64 != 0 {
		return 4
	}
	if unsafe.Sizeof(uintptr(0)) == 8 {
		return 8
	}
	return 4
}

func pointerSizeForPid(pid int) int {
	handle := GetProcessHandle(uint32(pid))
	if handle == 0 {
		return pointerSize()
	}
	defer closeHandle.Call(handle)
	return targetPointerSize(handle)
}

func readPointer(hProcess uintptr, address uintptr) (uintptr, error) {
	size := targetPointerSize(hProcess)
	buf := make([]byte, size)
	var n uintptr
	r1, _, err := readProcessMemoryProc.Call(
		hProcess,
		address,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&n)),
	)
	if r1 == 0 || n != uintptr(size) {
		return 0, fmt.Errorf("failed to read pointer at 0x%X: %v", address, err)
	}
	var value uint64
	for i := 0; i < size; i++ {
		value |= uint64(buf[i]) << (8 * i)
	}
	return uintptr(value), nil
}

func GetModuleInfo(processID uint32, moduleName string) (ModuleInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, processID)
	if err != nil {
		return ModuleInfo{}, fmt.Errorf("failed to create toolhelp32 snapshot: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	if err = windows.Module32First(snapshot, &me); err != nil {
		return ModuleInfo{}, fmt.Errorf("failed to get first module: %v", err)
	}

	for {
		currentModuleName := windows.UTF16ToString(me.Module[:])
		if strings.EqualFold(currentModuleName, moduleName) {
			return ModuleInfo{
				Name:        currentModuleName,
				FileName:    windows.UTF16ToString(me.ExePath[:]),
				lpBaseOfDll: me.ModBaseAddr,
				SizeOfImage: int(me.ModBaseSize),
				EntryPoint:  me.ModBaseAddr,
			}, nil
		}
		if err = windows.Module32Next(snapshot, &me); err != nil {
			break
		}
	}

	return ModuleInfo{}, fmt.Errorf("module not found")
}

func HexStringToByteArray(hexString string) []byte {
	hexString = strings.ReplaceAll(hexString, " ", "")
	hexString = strings.ReplaceAll(hexString, "0x", "")
	if len(hexString) == 0 || len(hexString)%2 != 0 {
		return nil
	}

	byteArray := make([]byte, len(hexString)/2)
	for i := 0; i < len(hexString); i += 2 {
		val, _ := strconv.ParseInt(hexString[i:i+2], 16, 64)
		byteArray[i/2] = byte(val)
	}

	return byteArray
}

func WriteBytes(pid int, address uintptr, aobString string, offsets ...uintptr) error {
	aob := HexStringToByteArray(aobString)
	if len(aob) == 0 {
		return fmt.Errorf("empty byte pattern")
	}
	if offsets == nil {
		offsets = []uintptr{0x0}
	}
	//fmt.Printf("Opening process with PID: %d\n %v", pid, aob)
	hProcess, _, err := openProcessProc.Call(
		uintptr(PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_QUERY_INFORMATION),
		uintptr(0),
		uintptr(uint32(pid)),
	)
	if hProcess == 0 {
		return fmt.Errorf("failed to open process: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))

	targetAddress, err := GetAddressFromOffsets(hProcess, address, offsets...)
	if err != nil {
		return err
	}

	var numberOfBytesWritten uint32
	res, _, writeErr := writeProcessMemory.Call(
		hProcess,
		targetAddress,
		uintptr(unsafe.Pointer(&aob[0])),
		uintptr(len(aob)),
		uintptr(unsafe.Pointer(&numberOfBytesWritten)),
	)

	if res == 0 {
		return fmt.Errorf("failed to write memory: %v", writeErr)
	}

	if numberOfBytesWritten != uint32(len(aob)) {
		return fmt.Errorf("only partial memory was written: expected %d bytes, but wrote %d bytes", len(aob), numberOfBytesWritten)
	}

	return nil
}

func WriteRaw(pid int, address uintptr, buffer []byte, sizeBytes int, offsets ...uintptr) error {
	hProcess, _, err := openProcessProc.Call(
		uintptr(PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_VM_READ),
		uintptr(0),
		uintptr(uint32(pid)),
	)
	if hProcess == 0 {
		return fmt.Errorf("failed to open process: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))

	targetAddress, err := GetAddressFromOffsets(hProcess, address, offsets...)
	if err != nil {
		return err
	}

	var numberOfBytesWritten uint32
	res, _, err := writeProcessMemory.Call(
		uintptr(hProcess),
		targetAddress,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(sizeBytes),
		uintptr(unsafe.Pointer(&numberOfBytesWritten)),
	)

	if res == 0 {
		return fmt.Errorf("failed to write memory: %v", err)
	}

	if numberOfBytesWritten != uint32(sizeBytes) {
		return fmt.Errorf("only partial memory was written: expected %d bytes, but wrote %d bytes", sizeBytes, numberOfBytesWritten)
	}

	return nil
}
