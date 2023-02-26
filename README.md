<h2 align="center">
AtomLdr: A DLL loader with evasive features
</h2>
</br>

### Disclaimer

#### This loader utilizes techniques taught in MalDev Academy. The training will be launched in the upcoming weeks on [maldevacademy.com](maldevacademy.com).

</br>

### Features:

- CRT library independent.
- The final DLL file, can run the payload by loading the DLL (executing its entry point), or by executing the exported `"Atom"` function via the command line.  
- DLL unhooking from \KnwonDlls\ directory, with **no RWX** sections.
- The encrypted payload is saved in the resource section and retrieved via custom code.
- AES256-CBC Payload encryption using custom no table/data-dependent branches using [ctaes](https://github.com/bitcoin-core/ctaes); this is one of the best custom AES implementations I've encountered.
- Aes Key & Iv Encryption.
- Indirect syscalls, utilizing [HellHall](https://github.com/Maldev-Academy/HellHall) with *ROP* gadgets (for the unhooking part).
- Payload injection using APC calls - alertable thread.
- Payload execution using APC - alertable thread.
- Api hashing using two different implementations of the `CRC32` string hashing algorithm.
- The total Size is 17kb + payload size (multiple of 16).

<br>

### How Does The Unhooking Part Work

AtomLdr's unhooking method looks like the following

![image](https://user-images.githubusercontent.com/111295429/221431770-e27726a7-ca3d-4ec3-8fa1-0e04f8405f83.png)

the program 
Unhooking from the \KnwonDlls\ directory is not a new method to bypass user-land hooks. However, this loader tries to avoid allocating **RWX** memory when doing so. This was obligatory to do in [KnownDllUnhook](https://github.com/NUL0x4C/KnownDllUnhook) for example, where **RWX** permissions were needed to replace the text section of the hooked modules, and at the same time allow execution of functions within these text sections.

This was changed in this loader, where it suspends the running threads, in an attempt to block any function from being called from within the targetted text sections, thus eliminating the need of having them marked as **RWX** sections before unhooking, making **RW** permissions a possible choice.

This approach, however, created another problem; when unhooking, `NtProtectVirtualMemory` syscall and others were using the syscall instruction inside of ntdll.dll module, as an indirect-syscall approach. Still, as mentioned above, the unhooked modules will be marked as **RW** sections, making it impossible to perform indirect syscalls, because the syscall instruction that we were jumping to, can't be executed now, so we had to jump to another *executable* place, this is where `win32u.dll` was used.

`win32u.dll` contains some syscalls that are GUI-related functions, making it suitable to jump to instead of ntdll.dll. win32u.dll is loaded (statically), but not included in the unhooking routine, which is done to insure that win32u.dll can still execute the syscall instruction we are jumping to.

The suspended threads after that are resumed.

It is worth mentioning that this approach may not be that efficient, and can be unstable, that is due to the thread suspension trick used. However, it has been tested with multiple processes with positive results, in the meantime, if you encountered any problems, feel free to open an issue.

<br>

### Usage

- [PayloadBuilder](https://github.com/NUL0x4C/AtomLdr/tree/main/PayloadBuilder) is compiled and executed with the specified payload, it will output a `PayloadConfig.pc` file, that contains the encrypted payload, and its encrypted key and iv.
- The generated `PayloadConfig.pc` file will then replace [this](https://github.com/NUL0x4C/AtomLdr/blob/main/AtomLdr/PayloadConfig.pc) in the `AtomLdr` project. 
- Compile the `AtomLdr` project as x64 Release.
- To enable debug mode, uncomment this [here](https://github.com/NUL0x4C/AtomLdr/blob/main/AtomLdr/Debug.h#L6).


<br>

### Demo (1)

- Executing `AtomLdr.dll` using rundll32.exe, running [Havoc](https://github.com/HavocFramework/Havoc) payload, and capturing a screenshot

![image](https://user-images.githubusercontent.com/111295429/221431188-8f1b6a04-c0ce-48d3-91b3-9f2ba1ce9385.png)

- `AtomLdr.dll`'s Import Address Table

![image](https://user-images.githubusercontent.com/111295429/221433130-c285f84f-8cb9-4e69-aeb8-549f3d69fd19.png)


<br>

### Demo - Debug Mode(2) 

- Running `PayloadBuilder.exe`, to encrypt `demon[111].bin` - a Havoc payload file

![image](https://user-images.githubusercontent.com/111295429/221431453-0f4b2840-3f03-4957-996b-dbdea605e9c0.png)

<br>

- Running `AtomLdr.dll` using rundll32.exe

![image](https://user-images.githubusercontent.com/111295429/221432698-cd358adc-a72a-40f2-8502-e47482f65a59.png)
![image](https://user-images.githubusercontent.com/111295429/221432709-5455bd08-014c-4c04-b774-22e6778c2783.png)

<br>

- Havoc capturing a screenshot, after payload execution

![image](https://user-images.githubusercontent.com/111295429/221432872-08ce8327-502f-45bb-be0e-040ce39bfabf.png)



<br>

### Based on 
- [ctaes](https://github.com/bitcoin-core/ctaes) 
- [WriteProcessMemoryAPC](https://www.x86matthew.com/view_post?id=writeprocessmemory_apc)
- [VX-API](https://github.com/vxunderground/VX-API)
