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

    DWORD hdr_image_base = p_NT_HDR->OptionalHeader.ImageBase;
    DWORD size_of_image = p_NT_HDR->OptionalHeader.SizeOfImage;
    DWORD entry_point_RVA = p_NT_HDR->OptionalHeader.AddressOfEntryPoint;
    DWORD size_of_headers = p_NT_HDR->OptionalHeader.SizeOfHeaders;

    /** Allocate Memory **/
    char* ImageBase = (char*) VirtualAlloc(NULL, size_of_image, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(ImageBase == NULL) {
        // Allocation failed
        return NULL;
    }

    /** Map PE sections in memory **/

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
            // We copy SizeOfRaw data bytes, from the offset PointertoRawData in the file
            memcpy(dest, PE_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        } else {
            memset(dest, 0, sections[i].Misc.VirtualSize);
        }
    }

    IMAGE_DATA_DIRECTORY* data_directory = p_NT_HDR->OptionalHeader.DataDirectory;

    /** Handle imports **/
    
    // load the address of the import descriptors array
    IMAGE_IMPORT_DESCRIPTOR* import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*) (ImageBase + data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // this array is null terminated
    for(int i=0; import_descriptors[i].OriginalFirstThunk != 0; ++i) {

        // Get the name of the dll, and import it
        char* module_name = ImageBase + import_descriptors[i].Name;
        HMODULE import_module = LoadLibraryA(module_name);
        if(import_module == NULL) {
            return NULL;
        }

        // the lookup table points to function names or ordinals => it is the IDT
        IMAGE_THUNK_DATA* lookup_table = (IMAGE_THUNK_DATA*) (ImageBase + import_descriptors[i].OriginalFirstThunk);

        // the address table is a copy of the lookup table at first
        // but we put the addresses of the loaded function inside => that's the IAT
        IMAGE_THUNK_DATA* address_table = (IMAGE_THUNK_DATA*) (ImageBase + import_descriptors[i].FirstThunk);

        // null terminated array, again
        for(int i=0; lookup_table[i].u1.AddressOfData != 0; ++i) {
            void* function_handle = NULL;

            // Check the lookup table for the adresse of the function name to import
            DWORD lookup_addr = lookup_table[i].u1.AddressOfData;

            if((lookup_addr & IMAGE_ORDINAL_FLAG) == 0) { //if first bit is not 1
                // import by name : get the IMAGE_IMPORT_BY_NAME struct
                IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME*) (ImageBase + lookup_addr);
                // this struct points to the ASCII function name
                char* funct_name = (char*) &(image_import->Name);
                // get that function address from it's module and name
                function_handle = (void*) GetProcAddress(import_module, funct_name);
            } else {
                // import by ordinal, directly
                function_handle = (void*) GetProcAddress(import_module, (LPSTR) lookup_addr);
            }

            if(function_handle == NULL) {
                return NULL;
            }

            // change the IAT, and put the function address inside.
            address_table[i].u1.Function = (DWORD) function_handle;
        }
    }

    /** Handle relocations **/

    //this is how much we shifted the ImageBase
    DWORD delta_VA_reloc = ((DWORD) ImageBase) - p_NT_HDR->OptionalHeader.ImageBase;

    // if there is a relocation table, and we actually shitfted the ImageBase
    if(data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 && delta_VA_reloc != 0) {

        //calculate the relocation table address
        IMAGE_BASE_RELOCATION* p_reloc = (IMAGE_BASE_RELOCATION*) (ImageBase + data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        
        //once again, a null terminated array
        while(p_reloc->VirtualAddress != 0) {

            // how any relocation in this block
            // ie the total size, minus the size of the "header", divided by 2 (those are words, so 2 bytes for each)
            DWORD size = (p_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/2;
            // the first relocation element in the block, right after the header (using pointer arithmetic again)
            WORD* reloc = (WORD*) (p_reloc + 1);
            for(int i=0; i<size; ++i) {
                //type is the first 4 bits of the relocation word
                int type = reloc[i] >> 12;
                // offset is the last 12 bits
                int offset = reloc[i] & 0x0fff;
                //this is the address we are going to change
                DWORD* change_addr = (DWORD*) (ImageBase + p_reloc->VirtualAddress + offset);

                // there is only one type used that needs to make a change
                switch(type){
                    case IMAGE_REL_BASED_HIGHLOW :
                        *change_addr += delta_VA_reloc;
                        break;
                    default:
                        break;
                }
            }

            // switch to the next relocation block, based on the size
            p_reloc = (IMAGE_BASE_RELOCATION*) (((DWORD) p_reloc) + p_reloc->SizeOfBlock);
        }
    }

    /** Map PE sections privileges **/

    //Set permission for the PE hader to read only
    DWORD oldProtect;
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