# Header Parser #
Parses header information of a binary (executable) file.  
PE, ELF, DEX, MachO, ZIP (JAR, DocX) are parsed in depth.  
Java.class, ART, .NET, NE, MS-DOS are recognized.  

The focus was on PE and ELF. 
The other types are handled less carefully but may be extended in the future.
As well as PE and ELF still have to be extended.


POSIX compliant.  
Compils and runs under
    - Linux 
    - Windows (x86/x64).  
    - OsX may work too.
    - Android in [Termux][1]:

[1]: https://termux.com/



## Version ##
1.11.5  
Last changed: 12.08.2021

## REQUIREMENTS ##
- Linux
   - Gcc
   - Building with cmake requires cmake.
- Windows
   - msbuild
   - [wdk]

**Remarks**  
The .vcxproj file is using `WindowsApplicationForDrivers10.0` as the `PlatformToolset`, which leads to smaller builds. 
If the WDK is not installed, the `PlatformToolset` may be changed to `v142` and it should compile without errors.

## BUILD ##
### Linux (gcc) & cmake ###
```bash
$ ./linuxBuild.sh [-t headerParser] [-m Release|Debug] [-h]  
```

### Linux (gcc) ###
```bash
$ mkdir build
$ gcc -o build/headerParser -Wl,-z,relro,-z,now -D_FILE_OFFSET_BITS=64 -Ofast src/headerParser.c src/utils/Converter.c  
```

Use `clang` istead off `gcc` in Termux on Android.

### Windows (MsBuild) ###
```bash
$ winBuild.bat [/t headerParser] [/m Release|Debug] [/b 32|64] [/rt] [/pdb] [/bt a\path] [/h]
```
This will run in a normal cmd.  
The correct path to your build tools may be passed as a parameter or changed in the script [winBuild.bat](winBuild.bat) itself.  


### Windows Context Menu ###
It may be convenient to add HeaderParser to the context menu to be able to right-click a file and header parse it.
In this scenario, you may use
```bash
$ addHeaderParserToShellCtxtMenu.bat /p "c:\HeaderParser.exe" [/l "Open in HeaderParser"]
```

 

## USAGE ##
```bash
$ ./headerParser a/file/name [options]
$ ./headerParser [options] a/file/name
```
Options:  
 * -h Print help.
 * -s:uint64_t Start offset in file. Default = 1.
 * -i:uint8_t Level of output info. 1 : minimal output (Default), 2 : extended output (basic header).
 * -f:string Force parsing a specific type, skipping magic value checks. Currently only "pe" is supported.
 * -offs: show file offsets of the printed values (for -i 2 or XX only options).
 * PE only options:
   * -dosh: Print DOS header.
   * -coffh: Print COFF header.
   * -opth: Print Optional header.
   * -sech: Print Section headers.
   * -exp: Print the Image Export Table (IMAGE_DIRECTORY_ENTRY_EXPORT).
   * -imp: Print the Image Import Table (IMAGE_DIRECTORY_ENTRY_IMPORT).
   * -res: Print the Image Resource Table (IMAGE_DIRECTORY_ENTRY_RESOURCE).
   * -crt: Print the Image Certificate Table (IMAGE_DIRECTORY_ENTRY_CERTIFICATE).
   * -cod: Directory to save found certificates in. (Needs -crt.)
   * -rel: Print the Image Base Relocation Table (IMAGE_DIRECTORY_ENTRY_BASE_RELOC).
   * -tls: Print the Image TLS Table (IMAGE_DIRECTORY_ENTRY_TLS).
   * -lcfg: Print the Image Load Config Table (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
   * -bimp: Print the Image Bound Import Table (IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT).
   * -dimp: Print the Image Delay Import Table (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT).
 * ELF only options:
   * -fileh: Print file header.
   * -progh: Print program headers.
   * -sech: Print section headers.
 
## EXAMPLE ##
```bash
$ ./headerParser a/file/name [-i 1]

HeaderData:
coderegions:
 (1) .text: ( 0x0000000000000400 - 0x000000000000fc00 )
 (2) .init ...
 (3) ...
headertype: PE|ELF|... (32|64)
bitness: 64-bit|32-bit|x-bit
endian: little|big
CPU_arch: Intel|Arm|...
Machine: ...
```

There is a difference between the header bitness (displayed in brackets following the `headertype`) and the bitness of the executable (program code). 
The header bitness is 32 or 64 bit for ELF, MACH-O and PE. 
The bitness of the executable (program code) may be different though.

An extended output will be printed, by setting "-i 2", whick will cover the basic headers.
```bash
$ ./headerParser a/file.exe -i 2

PE Image Dos Header:
...
Coff File Header:
...
Optional Header::
...
Section Header:
1 / x
...
2 / x
```

```bash
$ ./headerParser an/elf/file -i 2

ELF File header:
...
Program Header Table:
1 / x
...
2 / x
...
Section Header Table:
1 / y
...
2 / y
...
```

A more fine grained and/or extended printout is available with the PE or ELF only options.

### Offsets ###
If you think, the header starts somewhere in the file, you may pass an offset to it using the "-s" option.

### Forcing ###
If you think it is a PE file but the MZ or PE00 magic values are broken, try the "-f pe" option.


## ALTERNATIVE USAGE ##
HeaderParser may also be build as a shared library.  
Currently tested only on Linux.

### Build ###
```bash
./linuxBuild.sh -t headerParser_so [-m Release|Debug] [-h]
```
or plain:
```bash
mkdir build
gcc -fPIC -Wl,-z,relro,-z,now -shared -Ofast -D_FILE_OFFSET_BITS=64 -o build/libheaderparser.so src/headerParserLib.c src/utils/Converter.c -Wall 
```

### Usage ###
```c
// link library when compiling
// include
#include "src/HeaderData.h"
#include "src/headerParserLib.h"
...
// use library
size_t offset = 0;
uint8_t force = FORCE_NONE; // or FORCE_PE
HeaderData* data = getBasicHeaderParserInfo("a/file.path", offset, force);
// do stuff handling data
// ...
// clean up
freeHeaderData(data);
```

For PE files there is an extended parser available. 
```c
// include
#include "src/PEHeaderData.h"
#include "src/headerParserLibPE.h"
...
// use library
size_t offset = 0;
PEHeaderData* data = getPEHeaderData("a/file.path", offset);
// do stuff handling data
// ...
// clean up
freePEHeaderData(data);
```

### Python ###
Using the library is the preferred usage in python.  
On the python side, use [header_parser.py](src/header_parser.py).
```python

from src import header_parser

# initialization
header_parser.init("src/of/libheaderparser.so")
# default usage
data = header_parser.get_basic_info('a/file.src')
# passing a start offset
data = header_parser.get_basic_info('a/file.src', 10)
# passing a start offset and forcing PE parsing
data = header_parser.get_basic_info('a/file.src', 10, header_parser.FORCE_PE)
# convert cpu id and header type id into strings
cpu = header_parser.lib_header_parser.getHeaderDataHeaderType(data['cpu'])
header_type = header_parser.lib_header_parser.getHeaderDataArchitecture(data['headertype'])
```

## COPYRIGHT, CREDITS & CONTACT ## 
Published under [GNU GENERAL PUBLIC LICENSE](LICENSE).

#### Author ####
- Henning Braun ([henning.braun@fkie.fraunhofer.de](henning.braun@fkie.fraunhofer.de)) 

#### Co-Author, Icon Art ####
common_codeio.h, Icon.ico
- Viviane Zwanger ([viviane.zwanger@fkie.fraunhofer.de](viviane.zwanger@fkie.fraunhofer.de))
