#!/bin/bash -l

cd ../llvm-project

TEMP_OLD=../dev/temp-old
TEMP_NEW=../dev/temp-new
mkdir -p $TEMP_OLD
mkdir -p $TEMP_NEW

OLD_TAG=llvmorg-20.1.5
NEW_TAG=llvmorg-22.1.8

files=(
    "llvm/include/llvm/MC/MCInstrDesc.h"
    "llvm/include/llvm/MC/MCRegisterInfo.h"
    "llvm/include/llvm/TargetParser/Triple.h"
    "llvm/include/llvm/MC/TargetRegistry.h"
)

for f in "${files[@]}"
do
    git show $OLD_TAG:$f > $TEMP_OLD/$(basename $f)
    git show $NEW_TAG:$f > $TEMP_NEW/$(basename $f)
done

cd -
