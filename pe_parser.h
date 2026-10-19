#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <stdint.h>
#include <tlhelp32.h>

typedef struct {
    char     name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    
} pe_section;

typedef struct {
    uint16_t e_magic;
    int32_t e_lfanew;
    uint32_t pe_sig;
    uint16_t num_sections;
    uint16_t size_opt_header;
    pe_section sections[32];
} pe_parser;

typedef struct {
    char name[64];
    uint64_t base;
    uint32_t size;
} loaded_module;

char* whichModule(uint64_t addr, loaded_module lmMod[]) {
    int found = 0;
    int iter = 0;
    while ( lmMod[iter].size != 0 ) {
        if (addr >= lmMod[iter].base && addr < (lmMod[iter].base + lmMod[iter].size)) {
            return lmMod[iter].name;
        }

        if (lmMod[iter].base == 0) { break; }
        iter++;
    }

    return 0;
}

int RvaFileOffset(int rva, uint16_t numsections, pe_parser* sections) {
    for (size_t i = 0; i < numsections; i++) {
        if (rva >= sections->sections[i].virtual_address && 
            rva <= (sections->sections[i].virtual_address + sections->sections[i].virtual_size)) {
            return sections->sections[i].pointer_to_raw_data + (rva - sections->sections[i].virtual_address);
        }
    }
    return rva; // fallback: header region, RVA == file offset
}

int CmpFuncAddr(BYTE* disk_offset, BYTE* memory_offset, int extend) {
    if (memcmp(disk_offset, memory_offset, extend) == 0) {
        return 0; //clean
    } else { return 1; }  //hooked
}

char* DetermineHookType(BYTE* disk_offset, BYTE* memory_offset) {
    BYTE first_byte = *memory_offset;
    
    if (first_byte == 0xE9) return "Relative JMP";
    if (first_byte == 0x68) return "PUSH+RET";
    if (first_byte == 0xFF) {
        if (*(memory_offset+1) == 0x25) return "Indirect absolute JMP";
        return "Indirect JMP";
    }
    return "Unknown";
}

HANDLE lpPE(wchar_t dllPath[], pe_parser *p, BYTE ** sec_start, LPVOID * base) {
    HANDLE targetDll;

    targetDll = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD fileSize = GetFileSize(targetDll, NULL);
    *(base) = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    DWORD bytesRead = 0;
    ReadFile(targetDll, *base, fileSize, &bytesRead, NULL);

    

    p->e_magic = *(uint16_t*)((BYTE*)*base + 0x00); // MZ
    p->e_lfanew = *(int32_t*)((BYTE*)*base + 0x3C); // offset to nt headers
    p->pe_sig = *(uint32_t*)((BYTE*)*base + p->e_lfanew); // PE\0\0 SIGNATURE
    p->num_sections = *(uint16_t*)((BYTE*)*base + p->e_lfanew + 4 + 2); // OFFSET 2 SKIPPING THE PE SIG BYTES (4)
    p->size_opt_header = *(uint16_t*)((BYTE*)*base + p->e_lfanew + 4 + 16); // OFFSET 16 ^^^^^^^^^^^^^^^^^^^^^^^^^

    *(sec_start) = (BYTE*)*base + p->e_lfanew + 24 + p->size_opt_header;

    return targetDll;

    
}

void prsSec(pe_parser *p, BYTE ** sec_start) {
    for (int i = 0; i < p->num_sections; i++) {
        memcpy(p->sections[i].name, (BYTE*)*sec_start + (i * 40) + 0, 8);
        p->sections[i].virtual_size = *(uint32_t*)((BYTE*)*sec_start + (i * 40) + 8);
        p->sections[i].virtual_address = *(uint32_t*)((BYTE*)*sec_start + (i * 40) + 12);
        p->sections[i].size_of_raw_data = *(uint32_t*)((BYTE*)*sec_start + (i * 40) + 16);
        p->sections[i].pointer_to_raw_data = *(uint32_t*)((BYTE*)*sec_start + (i * 40) + 20);

        //printf("Name = %.8s\n VirtualSize = 0x%X\n VirtualAddress = 0x%X\n SizeOfRawData = 0x%X\n PointerToRawData = 0x%X\n",p.sections[i].name, p.sections[i].virtual_size, p.sections[i].virtual_address, p.sections[i].size_of_raw_data, p.sections[i].pointer_to_raw_data);
        //printf("RVAs from 0x%X to 0x%X belong to %.8s. Raw data starts at 0x%X. \n", p.sections[i].virtual_address, (p.sections[i].virtual_address+p.sections[i].virtual_size), p.sections[i].name, p.sections[i].pointer_to_raw_data);
        
    }
}

void EnumerateAllModules(loaded_module modules[]) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    
    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);
    
    int idx = 0;
    if (Module32First(hSnapshot, &me)) {
        do {
            strncpy(modules[idx].name, me.szModule, 64);
            modules[idx].base = (uint64_t)me.modBaseAddr;
            modules[idx].size = me.modBaseSize;
            idx++;
        } while (Module32Next(hSnapshot, &me));
    }
    
    modules[idx].size = 0; // terminator
    CloseHandle(hSnapshot);
}

#endif
