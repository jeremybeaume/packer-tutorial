import argparse
import lief
import os
import subprocess

def align(x, al):
    """ return <x> aligned to <al> """
    if x % al == 0:
        return x
    else:
        return x - (x % al) + al


def pad_data(data, al):
    """ return <data> padded with 0 to a size aligned with <al> """
    return data + ([0] * (align(len(data), al) - len(data)))


def compile_stub(input_cfile, output_exe_file, more_parameters = []):
    cmd = (["mingw32-gcc.exe", input_cfile, "-o", output_exe_file] # Force the ImageBase of the destination PE
        + more_parameters +
        ["-Wl,--entry=__start", # define the entry point
        "-nostartfiles", "-nostdlib", # no standard lib
        "-fno-ident",  "-fno-asynchronous-unwind-tables", # Remove unnecessary sections
        "-lkernel32" # Add necessary imports
        ])
    print("[+] Compiling stub : "+" ".join(cmd))
    subprocess.run(cmd)
    subprocess.run(["strip.exe", output_exe_file])

def pack_data(data) :
    KEY = 0xAA
    result = [0] * len(data)
    for i in range(0, len(data)):
        KEY = data[i] ^ KEY
        result[i] = KEY
    return result


if __name__ =="__main__" :

    parser = argparse.ArgumentParser(description='Pack PE binary')
    parser.add_argument('input', metavar="FILE", help='input file')
    parser.add_argument('-o', metavar="FILE", help='output', default="packed.exe")

    args = parser.parse_args()

    # Opens the input PE
    input_PE = lief.PE.parse(args.input)

    # Compiles the unpacker stub a first time, with no particular options
    compile_stub("unpack.c", "unpack.exe", more_parameters=[]);

    # open the unpack.exe binary
    unpack_PE = lief.PE.parse("unpack.exe")

    # we're going to keep the same alignment as the ones in unpack_PE,
    # because this is the PE we are modifying
    file_alignment = unpack_PE.optional_header.file_alignment
    section_alignment = unpack_PE.optional_header.section_alignment


    ASLR = (input_PE.optional_header.dll_characteristics & lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE != 0)
    if ASLR:
        output_PE = unpack_PE # we can use the current state of unpack_PE as our output
    else:
        # We need to add an empty section, ".alloc" just after the header
        # It's size will at least the size offcupied by the sections on the input PE

        # The RVA of the lowset section of input PE
        min_RVA = min([x.virtual_address for x in input_PE.sections]) # should be = 0x1000, the section alignment
        # The RVA of the end of the highest section
        max_RVA = max([x.virtual_address + x.size for x in input_PE.sections])

        # Now we create the section
        alloc_section = lief.PE.Section(".alloc")
        alloc_section.virtual_address = min_RVA
        alloc_section.virtual_size = align(max_RVA - min_RVA, section_alignment)
        alloc_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ
                                        | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
                                        | lief.PE.SECTION_CHARACTERISTICS.CNT_UNINITIALIZED_DATA)

        # to put the section just after ours, find the lowest section RVA in the stub
        min_unpack_RVA = min([x.virtual_address for x in unpack_PE.sections])
        # and compute how much we need to move to be exactly after the .alloc section
        shift_RVA = (min_RVA + alloc_section.virtual_size) - min_unpack_RVA

        # We need to recompile the stub to make room for the .alloc section, by shifting all its sections
        compile_parameters = [f"-Wl,--image-base={hex(input_PE.optional_header.imagebase)}"]

        for s in unpack_PE.sections:
            compile_parameters += [f"-Wl,--section-start={s.name}={hex(input_PE.optional_header.imagebase + s.virtual_address + shift_RVA )}"]

        # recompile the stub with the shifted sections
        compile_stub("unpack.c", "shifted_unpack.exe", compile_parameters)

        unpack_shifted_PE = lief.PE.parse("shifted_unpack.exe")

        # This would insert .alloc section at the end of the table, so the RVA would not be in order.
        # but Windows doesn' t seem to like it : the binary doesn' t load.
        # output_PE = unpack_shifted_PE
        # output_PE.add_section(alloc_section)

        # Here is how we make a completely new PE, copying the important properties
        # And adding the sections in order
        output_PE = lief.PE.Binary("pe_from_scratch", lief.PE.PE_TYPE.PE32)

        # Copy optional headers important fields
        output_PE.optional_header.imagebase = unpack_shifted_PE.optional_header.imagebase
        output_PE.optional_header.addressof_entrypoint = unpack_shifted_PE.optional_header.addressof_entrypoint
        output_PE.optional_header.section_alignment = unpack_shifted_PE.optional_header.section_alignment
        output_PE.optional_header.file_alignment = unpack_shifted_PE.optional_header.file_alignment
        output_PE.optional_header.sizeof_image = unpack_shifted_PE.optional_header.sizeof_image

        # make sure output_PE cannot move
        output_PE.optional_header.dll_characteristics = 0

        # copy the data directories (imports most notably)
        for i in range(0, 15):
            output_PE.data_directories[i].rva = unpack_shifted_PE.data_directories[i].rva
            output_PE.data_directories[i].size = unpack_shifted_PE.data_directories[i].size    

        # add the sections in order
        output_PE.add_section(alloc_section)
        for s in unpack_shifted_PE.sections:
            output_PE.add_section(s)
        
        # We now are ok to continue with the .packed section, as before


    # Create the a .packed section, with the packed PE inside :

    # read the whole file to be packed
    with open(args.input, "rb") as f:
        input_PE_data = f.read()

    # create the section in lief
    packed_data = pack_data(list(input_PE_data)) # pack the input file data
    packed_data = pad_data(packed_data, file_alignment) # pad with 0 to align with file alignment (removes a lief warning)

    packed_section = lief.PE.Section(".rodata")
    packed_section.content =  packed_data
    packed_section.size = len(packed_data)
    packed_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ
                                    | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)
    # We don't need to specify a Relative Virtual Address here, lief will just put it at the end, that doesn't matter.
    output_PE.add_section(packed_section)

    # remove the SizeOfImage, which should change, as we added a section. Lief will compute this for us.
    output_PE.optional_header.sizeof_image = 0


    # save the resulting PE
    if(os.path.exists(args.o)):
        # little trick here : lief emits no warning when it cannot write because the output
        # file is already opened. Using this function ensure we fail in this case (avoid errors).
        os.remove(args.o)

    builder = lief.PE.Builder(output_PE)
    builder.build()
    builder.write(args.o)


    