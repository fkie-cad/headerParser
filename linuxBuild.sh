#!/bin/bash

DP_FLAG=1
EP_FLAG=2

name=headerParser
def_target=${name}
pos_targets="app|sh|st|pck|cln|del"
target="app"
build_mode=2
mode="Release"
help=0
debug_print=$EP_FLAG

# Clean build directory from meta files
#
# @param $1 build directory
function clean() {
    local dir=$1

    echo "cleaning dir: $dir"

    if [[ ${dir} == "${ROOT}" ]]; then
        return 0
    fi

    cd ${dir} || return -1

    rm -r ./CMakeFiles 2> /dev/null
    rm -r ./CTestTestfile.cmake 2> /dev/null
    rm -r ./CMakeCache.txt 2> /dev/null
    rm -r ./cmake_install.cmake 2> /dev/null
    rm -rf ./tests 2> /dev/null
    rm -f ./*.cbp 2> /dev/null
    rm -r ./Makefile 2> /dev/null
    rm -rf ./debug 2> /dev/null
    rm -rf ./.cmake 2> /dev/null

    cd - || return -2

    return 0
}

# Delete build directory and all files in it
#
# @param $1 build directory
function delete() {
    local dir=$1

    echo "deleting dir: $dir"

    if [[ ${dir} == "${ROOT}" ]]; then
        return 0
    fi

    rm -rf ${dir} 2> /dev/null

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
    local ep=0

    if ! mkdir -p ${dir}; then
        return 1
    fi

    if [[ $((dp & $EP_FLAG)) == $EP_FLAG ]]; then
        ep=1
    fi
    dp=$((dp & ~$EP_FLAG))

    # if no space at -B..., older cmake (ubuntu 18) will not build
    if ! cmake -S ${ROOT} -B${dir} -DCMAKE_BUILD_TYPE=${mode} -DDEBUG_PRINT=${dp} -DERROR_PRINT=${ep}; then
        return 2
    fi

    if ! cmake --build ${dir} --target ${target}; then
        return 3
    fi

    # if [[ ${mode} == "Release" || ${mode} == "release" ]] && [[ ${target} == ${name} ]]; then
    #     sha256sum ${dir}/${target} | awk '{print $1}' > ${dir}/${target}.sha256
    # fi

    return 0
}

# Build a clean runnable package without metafiles.
#
# @param $1 cmake target
# @param $2 build directory
# @param $3 build mode
function buildPackage()
{
    local target=$1
    local dir=$2
    local mode=$3
    local dp=$4

    if ! buildTarget ${target} ${dir} ${mode} 0; then
        return 1
    fi

    if ! clean ${dir}; then
        return 4
    fi

    return 0
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
    echo "  * sh: build headerParser shared library"
    echo "  * st: build headerParser static library"
    echo "  * pck: build headerParser application and clean up build dir"
    echo "  * cln: clean build dir, remove cmake files"
    echo "  * del: delete build dir, i.e. delete all build targets"
    echo "-d Build in debug mode"
    echo "-r Build in release mode"
    echo "-h Print this."
    return 0;
}

while getopts ":p:t:hdr" opt; do
    case $opt in
    d)
        build_mode=1
        ;;
    h)
        help=1
        ;;
    p)
        debug_print="$OPTARG"
        ;;
    r)
        build_mode=2
        ;;
    t)
        target="$OPTARG"
        ;;
    \?)
        echo "Invalid option -$OPTARG" >&2
        ;;
    esac
done

if [[ ${help} == 1 ]]; then
    printHelp
    exit $?
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

release_build_dir="${ROOT}/build"
debug_build_dir="${ROOT}/build/debug"
if [[ $((build_mode & 2)) == 2 ]]; then
    mode="Release"
    build_dir=${release_build_dir}
else
    mode="Debug"
    build_dir=${debug_build_dir}
fi
echo "target: "${target}
echo "mode: "${mode}
echo "build_dir: "${build_dir}

if [[ ${target} == "cln" || ${target} == "clean" ]]; then
    clean ${build_dir}
    exit $?
elif [[ ${target} == "del" || ${target} == "delete" ]]; then
    delete ${build_dir}
    exit $?
elif [[ ${target} == "pck" ]]; then
    target=${name}_pck

    buildPackage ${name} ${release_build_dir} Release

    exit $?
else
    if [[ ${target} == "app" ]]; then
        target=${name}
    elif [[ ${target} == "sh" || ${target} == "shared" ]]; then
        target=${name}_sh
    elif [[ ${target} == "st" || ${target} == "static" ]]; then
        target=${name}_st
    elif [[ ${target} == "tso" ]]; then
        target=testHeaderParserLib
    elif [[ ${target} == "tpso" ]]; then
        target=testHeaderParserLibPE
    elif [[ ${target} == "dirun" ]]; then
        target=HPDirectoryRunner
    else
        echo "Unknown target: ${target}"
        exit $?
    fi

    buildTarget ${target} ${build_dir} ${mode} ${debug_print}

    exit $?
fi

exit $?
