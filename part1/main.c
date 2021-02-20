#include <stdio.h>
#include <stdlib.h>

#include <windows.h>
#include <winnt.h>

// loads a PE in memory, returns the entry point address
void* load_PE (char* PE_data);

int main(int argc, char** argv) {
    if(argc<2) {
        printf("missing path argument\n");
        return 1;
    }

    FILE* exe_file = fopen(argv[1], "rb");
    if(!exe_file) {
        printf("error opening file\n");
        return 1;
    }

    // Get file size : put pointer at the end
    fseek(exe_file, 0L, SEEK_END);
    // and read its position
    long int file_size = ftell(exe_file);
    // put the pointer back at the beginning
    fseek(exe_file, 0L, SEEK_SET);

    //allocate memory and read the whole file
    char* exe_file_data = malloc(file_size+1);

    //read whole file
    size_t n_read = fread(exe_file_data, 1, file_size, exe_file);
    if(n_read != file_size) {
        printf("reading error (%d)\n", n_read);
        return 1;
    }

    // load the PE in memory
    printf("[+] Loading PE file\n");
    void* start_address = load_PE(exe_file_data);
    if(start_address) {
        // call its entry point
        ((void (*)(void)) start_address)();
    }
    return 0;
}

void* load_PE (char* PE_data) {

    /** Parse header **/

    IMAGE_DOS_HEADER* p_DOS_HDR  = (IMAGE_DOS_HEADER*) PE_data;
    IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*) (((char*) p_DOS_HDR) + p_DOS_HDR->e_lfanew);

    DWORD ASLR = p_NT_HDR->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    DWORD hdr_image_base = p_NT_HDR->OptionalHeader.ImageBase;
    DWORD size_of_image = p_NT_HDR->OptionalHeader.SizeOfImage;
    DWORD entry_point_RVA = p_NT_HDR->OptionalHeader.AddressOfEntryPoint;

    /** Allocate Memory **/

    char* ImageBase = NULL;

    if(ASLR) {
        ImageBase = (char*) VirtualAlloc(NULL, size_of_image, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if(ImageBase == NULL) {
            // Allocation failed
            return (void*) 0x41414141;
        }
    }

    /** Map PE sections in memory **/

    DWORD oldProtect;

    VirtualProtect(ImageBase, p_NT_HDR->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &oldProtect);
    memcpy(ImageBase, PE_data, p_NT_HDR->OptionalHeader.SizeOfHeaders);


    // Section headers starts right after the IMAGE_NT_HEADERS struct, so we do some pointer arithmetic-fu here.
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*) (p_NT_HDR + 1); 

    // For each sections
    for(int i=0; i<p_NT_HDR->FileHeader.NumberOfSections; ++i) {
        // calculate the VA we need to copy the content, from the RVA 
        // section[i].VirtualAddress is a RVA, mind it
        char* dest = ImageBase + sections[i].VirtualAddress; 

        // check if there is Raw data to copy
        if(sections[i].SizeOfRawData > 0) {
            // A VirtualProtect to be sure
            VirtualProtect(dest, sections[i].SizeOfRawData, PAGE_READWRITE, &oldProtect);
            // We copy SizeOfRaw data bytes, from the offset PointertoRawData in the file
            memcpy(dest, PE_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        } else {
            // if no raw data to copy, we just put zeroes, based on the VirtualSize
            VirtualProtect(dest, sections[i].Misc.VirtualSize, PAGE_READWRITE, &oldProtect);
            memset(dest, 0, sections[i].Misc.VirtualSize);
        }
    }

    /** Map PE sections privileges **/

    //Set permission for the PE hader to read only
    VirtualProtect(ImageBase, p_NT_HDR->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtect);

    for(int i=0; i<p_NT_HDR->FileHeader.NumberOfSections; ++i) {
        char* dest = ImageBase + sections[i].VirtualAddress;
        DWORD s_perm = sections[i].Characteristics;
        DWORD v_perm = 0; //flags are not the same between virtal protect and the section header
        if(s_perm & IMAGE_SCN_MEM_EXECUTE) {
            v_perm = (s_perm & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else {
            v_perm = (s_perm & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        }
        VirtualProtect(dest, sections[i].Misc.VirtualSize, v_perm, &oldProtect);
    }

    return (void*) (ImageBase + entry_point_RVA);
}