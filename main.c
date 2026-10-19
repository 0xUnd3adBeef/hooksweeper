#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "pe_parser.h"

// HookSweeper

void HookTarget() {
    return;
}

int main(int argc, char* argv[]) {
    printf("Starting...\n");
    fflush(stdout);

    { // Hook install (could totally have used detours now that i think about it.)
        /// HOOK   
        FARPROC target = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateJobObject");
        DWORD oldProtect;
        if (!VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            printf("VirtualProtect failed: %d\n", GetLastError());
            return 1;
        }
        printf("VirtualProtect succeeded\n");

        BYTE* src = (BYTE*)target;
        BYTE* dst = (BYTE*)HookTarget;
        src[0] = 0xFF;
        src[1] = 0x25;
        *(uint32_t*)(src + 2) = 0x00000000;
        *(uint64_t*)(src + 6) = (uint64_t)dst;
        printf("Bytes written: %02X %02X\n", src[0], src[1]);
        fflush(stdout);
        fflush(stdout);
        printf("Target address: %p\n", target);
        printf("First byte after patch: %02X\n", *(BYTE*)target);

    /// HOOK
    }


    fflush(stdout);


    pe_parser p;
    BYTE * sec_start;
    LPVOID base;
    HANDLE hNtdll = lpPE(L"C:\\Windows\\System32\\ntdll.dll", &p, &sec_start, &base); // or known clean ntdll copy


    prsSec(&p, &sec_start);
    /*
    printf("RVA 0x1000    -> file offset 0x%X\n", RvaFileOffset(0x1000, p.num_sections, &p));
    printf("RVA 0x118000  -> file offset 0x%X\n", RvaFileOffset(0x118000, p.num_sections, &p));
    printf("RVA 0x1EC000  -> file offset 0x%X\n", RvaFileOffset(0x1EC000, p.num_sections, &p));
    */

    uint32_t EDRva = *(uint32_t*)((BYTE*)base + p.e_lfanew + 24 + 112);
    int edrvaoffset = RvaFileOffset(EDRva, p.num_sections, &p);
    printf("RVA 0x%X  -> file offset 0x%X\n", EDRva, edrvaoffset);

    IMAGE_EXPORT_DIRECTORY* ied = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)base + edrvaoffset);

    //printf("Name = 0x%X\nBase = 0x%X\nNumberOfFunctions = 0x%X\nNumberOfNames = 0x%X\nAddressOfFunctions = 0x%X\nAddressOfNames = 0x%X\nAddressOfNameOrdinals = 0x%X\n", ied->Name, ied->Base, ied->NumberOfFunctions, ied->NumberOfNames, ied->AddressOfFunctions, ied->AddressOfNames, ied->AddressOfNameOrdinals);

    int RVAArray = RvaFileOffset(ied->AddressOfNames, p.num_sections, &p);
    int FUNCArray = RvaFileOffset(ied->AddressOfFunctions, p.num_sections, &p);
    int ORDNArray = RvaFileOffset(ied->AddressOfNameOrdinals, p.num_sections, &p);
    int targRva = 0;

    HMODULE ntdll_base = GetModuleHandleW(L"ntdll.dll"); // grab potentially poisoned copy


    for (size_t i = 0; i < ied->NumberOfNames; i++) {
        uint32_t name_RVAOFFSET = *(uint32_t*)((BYTE*)base + RVAArray + (i*4));
        uint16_t ordinal = *(uint16_t*)((BYTE*)base + ORDNArray + (i*2));
        uint32_t ordn_RVAOFFSET = *(uint32_t*)((BYTE*)base + FUNCArray + (ordinal*4));
        char* funcName = ((BYTE*)base + RvaFileOffset(name_RVAOFFSET, p.num_sections, &p));

    /*
        printf("\nFunc name = %s\n", funcName);
        printf("Func RVA = 0x%X\n", ordn_RVAOFFSET);
    */
        // From here we can compare

        targRva = ordn_RVAOFFSET;

        BYTE* dskoffset = (BYTE*)base + RvaFileOffset(targRva, p.num_sections, &p);
        BYTE* memoffset = (BYTE*)ntdll_base + targRva;

        if (memcmp(funcName, "Nt", 2)== 0) {
            if (CmpFuncAddr(dskoffset, memoffset, 16) == 1) {
            char* type = DetermineHookType(dskoffset, memoffset);
            printf("\n[HOOKED] %s | Type : %s", funcName, type);
            //dsk
            printf("\n      Disk Bytes -> \n        ");
            for (int i = 0; i < 16; i++) {
                printf("%02X ", *(dskoffset+i));
            }
            
            //mem
            printf("\n      Memory Bytes (potential hook) -> \n        ");
            for (int i = 0; i < 16; i++) {
                printf("%02X ", *(memoffset+i));
            }
            }
        }
    }

    // IAT Analysis (Hooks)
    /*
        Import Address Table 

        The analogy for IAT is you have :
        +------------+---------------+
        | Name       | Phone number  |
        +------------+---------------+
        which roughly translates to
        +------------+---------------------+
        | FunctName  | Code start Address  |
        +------------+---------------------+

        But the scanning is done on own process OR target process NOT on dll & memory dll comp like inline
        Entry 0 was at +112, each entry is 8 bytes (4 RVA + 4 size), so entry 1 is at +120.
            Each entry in the import directory is an IMAGE_IMPORT_DESCRIPTOR (20 bytes) :

                +0 OriginalFirstThunk RVA -> points to INT (names, untouched at runtime)
                +12 Name RVA -> points to the DLL name string
                +16 FirstThunk RVA -> points to IAT (this is what gets patched by hooks)
        while (current descriptor is not all zeros) -> process it, advance by 20 bytes
            
    */

    pe_parser pself;
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    BYTE * sec_start_self;
    LPVOID base_self;
    HANDLE hSelf = lpPE(selfPath, &pself, &sec_start_self, &base_self);
    
    prsSec(&pself, &sec_start_self);


    HMODULE hHandle1 = GetModuleHandle(NULL);
    uint32_t DDe1RVA = *(uint32_t*)(base_self + pself.e_lfanew + 24 + 120);
    int DDe1FileOffset = RvaFileOffset(DDe1RVA, pself.num_sections, &pself);
    IMAGE_IMPORT_DESCRIPTOR* iidCDescriptorRVA = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hHandle1 + DDe1RVA);

    char DllName[400];
    int name_offset;
    int addr_offset;
    char* name;
    uint64_t addr;
    int modcount = 0;
    DllName[0] = '1';
    uint64_t* iat = (uint64_t*)((BYTE*)hHandle1 + iidCDescriptorRVA->FirstThunk); 
    loaded_module modules[256];

    printf("\nDDe1RVA = 0x%X\n", DDe1RVA); 
    
    EnumerateAllModules(modules);

    while (iidCDescriptorRVA->Name != 0) {
        strcpy(DllName,  ((BYTE*)base_self + (RvaFileOffset(iidCDescriptorRVA->Name, pself.num_sections, &pself))));

        BYTE* dll_base = (BYTE*)GetModuleHandleA(DllName);
        int lfanew = *(int32_t*)(dll_base + 0x3C);
        uint32_t sdllimg = *(uint32_t*)(dll_base + lfanew + 24 + 56);

        uint64_t INTSlotOffset = 1;
        uint64_t IATSlotOffset = 1;
        /*
            For some reason im completely missing i have trouble understanding the concept of RVAs and Offsets which seem very simple 
            but when i try to use them and apply them in my use case i just fail to organize it in my head (i MIGHT be slow)
            When module is LOADED in memory:  Virtual Address = ModuleBase + RVA
            When module is on DISK:           File Offset = complicated (must convert via sections)
        */


        for (int i = 0; INTSlotOffset != 0; i++) { // IAT walk -> Check 
            INTSlotOffset = RvaFileOffset(iidCDescriptorRVA->OriginalFirstThunk, pself.num_sections, &pself) + (8*i);
            IATSlotOffset = RvaFileOffset(iidCDescriptorRVA->FirstThunk, pself.num_sections, &pself) + (8*i); // WORST code EVER ?
            if (*(uint64_t*)((BYTE*)base_self + INTSlotOffset) == 0) { break; }; // Break out of loop if name = 0 

            name_offset = RvaFileOffset((*(uint64_t*)((BYTE*)base_self + INTSlotOffset)), pself.num_sections, &pself);
            addr_offset = RvaFileOffset((*(uint64_t*)((BYTE*)base_self + IATSlotOffset)), pself.num_sections, &pself);

            name = (char*)(base_self + name_offset + 2);
            addr = *(uint64_t*)((BYTE*)hHandle1 + iidCDescriptorRVA->FirstThunk + (i * 8));

            //printf("Name = %s\nAddr = 0x%X\n", name, addr);
            if (addr < (uint64_t)dll_base || addr >= (uint64_t)dll_base + sdllimg) { // TODO : Add forwarding detection (to reduce false positives)
                char* owner = whichModule(addr, modules);
                if (owner == 0) {
                    printf("[HOOKED] %s -> 0x%llX\n", name, addr);
                } else {printf("[FORWARDED] %s -> 0x%llX | %s\n", name, addr, owner);}
                    
            }
        }
        

        iidCDescriptorRVA++;
    }

    printf("Ended Normally.\n");



    VirtualFree(base, 0, MEM_RELEASE);
    CloseHandle(hNtdll);
    return 0;
}
