#!/bin/bash

DP_FLAG_DEBUG=1
DP_FLAG_ERROR=2

BUILD_FLAG_STATIC=1

MODE_DEBUG=1
MODE_RELEASE=2

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

release_build_dir="${ROOT}/build"
debug_build_dir="${ROOT}/build/debug"

name=headerParser
pos_targets="app|sh|st|cln|del"
def_target="app"
target=
build_mode=$MODE_RELEASE
build_flags=0
help=0
clean=0
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

    if [[ ${type} == 1 ]]; then
        echo "cleaning build dir: $dir"
        rm -rf ${dir}/*.o 2> /dev/null
    elif [[ ${type} == 2 ]]; then
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
    local mode=$3
    local dp=$4
    local build_flags=$5
    local ep=0

    if ! mkdir -p ${dir}; then
        return 1
    fi

    if [[ $((dp & $DP_FLAG_ERROR)) == $DP_FLAG_ERROR ]]; then
        ep=1
    fi
    dp=$((dp & ~$DP_FLAG_ERROR))

    local flags=""
    if [[ ${mode} == $MODE_DEBUG ]]; then
        flags="-Wl,-z,relro,-z,now -D_FILE_OFFSET_BITS=64 -Wall -pedantic -Wextra -ggdb -O0 -Werror=return-type -Werror=overflow -Werror=format"
    else
        flags="-Wl,-z,relro,-z,now -D_FILE_OFFSET_BITS=64 -Wall -pedantic -Wextra -Ofast -Werror=return-type -Werror=overflow -Werror=format"
    fi

    if [[ $((build_flags & $BUILD_FLAG_STATIC)) == $BUILD_FLAG_STATIC ]]; then
        flags="${flags} -static"
    fi

    local dpf=
    if [[ $dp > 0 ]]; then
        dpf=-DDEBUG_PRINT=$dp
    fi

    local epf=
    if [[ $ep > 0 ]]; then
        epf=-DERROR_PRINT
    fi
    
    
    local bin_name=$name
    local app_src="src/headerParser.c src/pe/PEHeader.c src/pe/PEHeaderOffsets.c"
    local sh_src="src/headerParserLib.c src/pe/PEHeader.c src/pe/PEHeaderOffsets.c"
    
    case $target in
        "app")
            gcc -o $dir/$bin_name $flags $dpf $epf -Ofast $app_src
            ;;
            
        "sh" | "shared")
            gcc -shared -fPIC $flags $dpf $epf -Ofast -o $dir/lib${bin_name}.so $sh_src
            ;;
            
        "st" | "static")
            if ! mkdir -p ${dir}/st; then
                return $?
            fi
            
            gcc $flags -o ${dir}/st/headerParserLib.o $ROOT/src/headerParserLib.c 
            gcc $flags -o ${dir}/st/PEHeader.o $ROOT/src/pe/PEHeader.c
            gcc $flags -o ${dir}/st/PEHeaderOffsets.o $ROOT/src/pe/PEHeaderOffsets.c
            
            ar rcs $dir/lib${bin_name}.a ${dir}/st/*.o
            ;;
            
        *)
            echo "Unknown target: ${target}"
            ;;
    esac

    return $?
}

function printUsage() {
    echo "Usage: $0 [-t ${pos_targets}] [-m Debug|Release] [-h]"
    echo "Default: $0 [-t app -r]"
    return 0;
}

function printHelp() {
    printUsage
    echo ""
    echo "-t A possible target: ${pos_targets}"
    echo "  * app: build headerParser application"
    echo "  * sh: build headerParser as a shared library"
    echo "  * st: build headerParser as a static library"
    echo "-d Build in debug mode"
    echo "-r Build in release mode"
    echo "-s Build statically linked binary"
    echo "-c clean up build dir"
    echo "-x delete all files in build dir"
    echo "-h Print this."
    return 0;
}

while (("$#")); do
    case "$1" in
        -c | -cln | --clean)
            clean=1
            shift 1
            ;;
        -d | --debug)
            build_mode=$MODE_DEBUG
            shift 1
            ;;
        -r | --release)
            build_mode=$MODE_RELEASE
            shift 1
            ;;
        -p | -dp | --debug-print)
            debug_print=$2
            shift 2
            ;;
        -s | --static)
            build_flags=$((build_flags | $BUILD_FLAG_STATIC))
            shift 1
            ;;
        -t | --target)
            target=$2
            shift 2
            ;;
        -h | --help)
            help=1
            break
            ;;
        -x | --delete)
            clean=2
            break
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

if [[ ${usage} == 1 ]]; then
    printUsage
    exit $?
fi

if [[ ${help} == 1 ]]; then
    printHelp
    exit $?
fi

if [[ $((build_mode & $MODE_RELEASE)) == $MODE_RELEASE ]]; then
    mode="Release"
    build_dir=${release_build_dir}
else
    mode="Debug"
    build_dir=${debug_build_dir}
fi

if [[ -z ${target} && ${clean} == 0 ]]; then
    target=$def_target
fi

echo "clean: "${clean}
echo "target: "${target}
echo "mode: "${mode}
echo "build_dir: "${build_dir}
echo "build_flags: "${build_flags}
echo -e

if [[ ${clean} > 0 ]]; then
    clean ${build_dir} ${clean} 
fi

if [[ -n ${target} ]]; then
    buildTarget ${target} ${build_dir} ${mode} ${debug_print} ${build_flags}
fi

exit $?
