# Header Parser #
Parses header information of a binary (executable) file.  
PE, ELF, DEX, MachO, ZIP (JAR, DocX) are parsed in depth.  
Java.class, ART, .NET, NE, MS-DOS are recognized.  

The focus was on PE and ELF. 
The other types are handled less carefully but may be extended in the future.
As well as PE and ELF still have to be extended.


POSIX compliant.  
Compilable under Linux and Windows (x86/x64).  
OsX may work too.


## Version ##
1.10.1  
Last changed: 17.12.2020

## REQUIREMENTS ##
- A decent c compiler (gcc or msbuild) is required.  
- Building with cmake requires cmake.  

## BUILD ##
### Linux & cmake ###
```bash
$ ./linuxBuild.sh [-t headerParser] [-m Release|Debug] [-h]  
```

### GCC & Linux commandline ###
```bash
$ mkdir build
$ gcc -o build/headerParser -Wl,-z,relro,-z,now -D_FILE_OFFSET_BITS=64 -Ofast src/headerParser.c  
```

### MsBuild & Windows & cmake ###
```bash
$ ./winBuild.bat [/t headerParser] [/b 32|64] [/m Release|Debug] [/h]
```
The correct path to your build tools may be passed as a parameter or changed in the script [winBuild.bat](winBuild.bat) itself.  
Thats the place to correct the path to your cmake installation as well.

 

## USAGE ##
```bash
$ ./headerParser a/file/name [options]
$ ./headerParser [options] a/file/name
```
Possible options:  
 * -h Print help.
 * -s:uint64_t Start offset in file. Default = 1.
 * -i:uint8_t Level of output info. 1 : minimal output (Default), 2 : extended output, 3 : extended output with offset info.
 * -f:string Force parsing a specific type, skipping magic value checks. Currently only "pe" is supported.
 * PE only options:
   * -iimp: Print the Image Import Table (IMAGE_DIRECTORY_ENTRY_IMPORT). (Needs -i > 1.)
   * -iexp: Print the Image Export Table (IMAGE_DIRECTORY_ENTRY_EXPORT). (Needs -i > 1.)
   * -ires: Print the Image Resource Table (IMAGE_DIRECTORY_ENTRY_RESOURCE). (Needs -i > 1.)
   * -irel: Print the Image Base Relocation Table (IMAGE_DIRECTORY_ENTRY_BASE_RELOC). (Needs -i > 1.)
   * -icrt: Print the Image Certificate Table (IMAGE_DIRECTORY_ENTRY_CERTIFICATE). (Needs -i > 1.)
   * -cod: Directory to save found certificates in. (Needs -icrt.)
   * -idimp: Print the Image Delay Import Table (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT). (Needs -i > 1.)
   * -ilcfg: Print the Image Load Config Table (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) (Needs -i > 1.)
 
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

A not yet complete but extended output will be printed, by setting "-i 2"
```bash
$ ./headerParser a/file/name 2

file or dos header
...
section header 1/x
...
section header 2/x
...
```
The output is not yet formatted very well.

### Offsets ###
If you think, the header starts somewhere in the file, you may pass an offset to it using the "-s" option.

### Forcing ###
If you think it is a PE file but the MZ or PE00 magic values are broken, try the "-f pe" option.


## ALTERNATIVE USAGE ##
HeaderParser may also be build as a shared library.  
Currently tested only on Linux.

### Build ###
```bash
./linuxBuild.sh headerParser_shared
```
or plain:
```bash
gcc -fPIC -shared -O2 -o libheaderparser.so  headerParserLib.c -Wall 
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
