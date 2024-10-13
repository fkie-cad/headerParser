#!/bin/bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

release_build_dir="${ROOT}/build"
debug_build_dir="${ROOT}/build/debug"

DP_FLAG_DEBUG=1
DP_FLAG_ERROR=2

BUILD_FLAG_STATIC=1

MODE_DEBUG=1
MODE_RELEASE=2

BUILD_TARGET_CLN=1
BUILD_TARGET_DEL=2
BUILD_TARGET_APP=4
BUILD_TARGET_SH=8
BUILD_TARGET_ST=0x10

name=headerParser
pos_targets="-app|-sh|-st|-cln|-del"
def_target=BUILD_TARGET_APP
target=0
build_mode=$MODE_RELEASE
build_flags=0
usage=0
help=0
verbose=0
debug_print=$DP_FLAG_ERROR

# Clean build directory from meta files
#
# @param $1 build directory
function clean() {
    local dir=$1
    local type=$2

    if [[ ${dir} != "${release_build_dir}" ]] && [[ ${dir} != "${debug_build_dir}" ]]; then
        echo [e] Invalid clean dir!
        return
    fi

    if (( ${type} == 1 )); then
        echo "cleaning build dir: $dir"
        rm -rf ${dir}/*.o 2> /dev/null
    elif (( ${type} == 2 )); then
        echo "deleting dir: $dir"
        rm -rf ${dir}/* 2> /dev/null
    fi

    return 0
}

# CMake build a target
#
# @param $1 cmake target
# @param $2 build directory
# @param $3 build mode
function buildTarget() {
    local target=$1
    local dir=$2
    local build_mode=$3
    local dp=$4
    local build_flags=$5
    local ep=0

    if [[ $verbose == 1 ]]; 
    then
        echo "buildTarget()"
        echo   "target="$target
        echo   "dir="$dir
        echo   "build_mode="$build_mode
        echo   "dp="$dp
        echo   "build_flags="$build_flags
    fi

    if ! mkdir -p ${dir}; then
        return 1
    fi

    if (( $((dp & $DP_FLAG_ERROR)) == $DP_FLAG_ERROR )); then
        ep=1
    fi
    dp=$((dp & ~$DP_FLAG_ERROR))

    local flags="-Wl,-z,relro,-z,now -D_FILE_OFFSET_BITS=64 -Wall -pedantic -Wextra -Werror=return-type -Werror=overflow -Werror=format"
    if (( ${build_mode} == $MODE_DEBUG )); then
        flags="${flags} -ggdb -O0"
    else
        flags="${flags} -Ofast"
    fi

    if (( $((build_flags & $BUILD_FLAG_STATIC)) == $BUILD_FLAG_STATIC )); then
        flags="${flags} -static"
    fi

    local dpf=
    if (( $dp > 0 )); then
        dpf=-DDEBUG_PRINT=$dp
    fi

    local epf=
    if (( $ep > 0 )); then
        epf=-DERROR_PRINT
    fi
    
    
    local bin_name=$name
    local app_src="src/headerParser.c src/pe/PEHeader.c src/pe/PEHeaderOffsets.c"
    local sh_src="src/headerParserLib.c src/pe/PEHeader.c src/pe/PEHeaderOffsets.c"
    
    case $target in
        $((BUILD_TARGET_APP)))
            gcc $flags $dpf $epf -o $dir/$bin_name $app_src
            ;;
            
        $((BUILD_TARGET_SH)))
            gcc -shared -fPIC $flags $dpf $epf -o $dir/lib${bin_name}.so $sh_src
            ;;
            
        $((BUILD_TARGET_ST)))
            if ! mkdir -p ${dir}/st; then
                return $?
            fi
            
            gcc $flags -c -o ${dir}/st/headerParserLib.o $ROOT/src/headerParserLib.c 
            gcc $flags -c -o ${dir}/st/PEHeader.o $ROOT/src/pe/PEHeader.c
            gcc $flags -c -o ${dir}/st/PEHeaderOffsets.o $ROOT/src/pe/PEHeaderOffsets.c
            
            ar rcs $dir/lib${bin_name}.a ${dir}/st/*.o
            ;;
            
        *)
            echo "Unknown target: ${target}"
            ;;
    esac

    return $?
}

function printUsage() {
    echo "Usage: $0 [${pos_targets}] [-d|-r] [-h]"
    echo "Default: $0 [-app -r]"
    return 0;
}

function printHelp() {
    printUsage
    echo ""
    echo "Possible targets: ${pos_targets}"
    echo "  * -app: build headerParser application"
    echo "  * -sh: build headerParser as a shared library"
    echo "  * -st: build headerParser as a static library"
    echo "-d Build in debug mode"
    echo "-r Build in release mode"
    echo "-s Build statically linked binary"
    echo "-c Clean up build dir"
    echo "-x Delete all files in build dir"
    echo "-h Print this."
    return 0;
}

while (("$#")); do
    case "$1" in
        -a | -app | --user-appliation)
            target=$(( target | BUILD_TARGET_APP ))
            shift 1
            ;;
        -c | -cln | --clean)
            target=$(( target | BUILD_TARGET_CLN ))
            shift 1
            ;;
        -d | --debug)
            build_mode=$MODE_DEBUG
            shift 1
            ;;
        -h | --help)
            help=1
            break
            ;;
        -p | -dp | --debug-print)
            debug_print=$2
            shift 2
            ;;
        -r | --release)
            build_mode=$MODE_RELEASE
            shift 1
            ;;
        -s | --static)
            build_flags=$((build_flags | $BUILD_FLAG_STATIC))
            shift 1
            ;;
        -sh | --shared-library)
            target=$((target | $BUILD_TARGET_SH))
            shift 1
            ;;
        -st | --static-library)
            target=$((target | $BUILD_TARGET_ST))
            shift 1
            ;;
        -v | --verbose)
            verbose=1
            shift 1
            ;;
        -x | --delete)
            target=$(( target | BUILD_TARGET_DEL ))
            shift 1
            ;;
        -* | --usage)
            usage=1
            break
            ;;
        *) # No more options
            break
            ;;
    esac
done

if (( ${usage} == 1 )); then
    printUsage
    exit $?
fi

if (( ${help} == 1 )); then
    printHelp
    exit $?
fi

# set build dir
if (( $((build_mode & $MODE_RELEASE)) == $MODE_RELEASE )); then
    build_dir=${release_build_dir}
else
    build_dir=${debug_build_dir}
fi

# set default target
if (( $target == 0 )); then
    target=$BUILD_TARGET_APP
fi

if (( $verbose == 1 )); 
then
    echo "target: "${target}
    echo "  clean: "$(( (target & BUILD_TARGET_CLN) > 0 ))
    echo "  del: "$(( (target & BUILD_TARGET_DEL) > 0 ))
    echo "  app: "$(( (target & BUILD_TARGET_APP) > 0 ))
    echo "  sh: "$(( (target & BUILD_TARGET_SH) > 0 ))
    echo "  st: "$(( (target & BUILD_TARGET_ST) > 0 ))
    echo "build_mode: "${build_mode}
    echo "debug_print: "${debug_print}
    echo "build_dir: "${build_dir}
    echo -e
fi


#
# build set targets
#

if (( $((target & BUILD_TARGET_CLN)) == $BUILD_TARGET_CLN )); then
    clean ${build_dir} 1
fi
if (( $((target & BUILD_TARGET_DEL)) == $BUILD_TARGET_DEL )); then
    clean ${build_dir} 2
fi

if (( $target > $BUILD_TARGET_DEL )); 
then
    buildTarget ${target} ${build_dir} ${build_mode} ${debug_print} ${build_flags}
fi

exit $?
