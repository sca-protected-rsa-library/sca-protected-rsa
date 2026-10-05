#!/bin/sh
# Builds the two firmware images shipped with the paper: the protected
# implementation with the window table re-permuted on every iteration
# (BR_PERM_EVERY_ITER), and the unprotected br_rsa_i31_private baseline.
set -e
OUT=paper
PREFIX=${PREFIX:-arm-none-eabi}
BASE_DEFINES="-DSTM32F4 -DCORTEX_M4 -DWITH_PERFORMANCE_BENCHMARKING"
mkdir -p "$OUT"

build() {                       # $1 = name, $2 = extra -D flags
	make clean >/dev/null
	make main.bin main.elf DEFINES="$BASE_DEFINES $2" >/dev/null 2>&1
	cp main.elf "$OUT/$1.elf"
	"$PREFIX"-strip --strip-all -R .comment "$OUT/$1.elf"
	"$PREFIX"-objcopy -Obinary "$OUT/$1.elf" "$OUT/$1.bin"
	if ! cmp -s "$OUT/$1.bin" main.bin; then
		echo "ERROR: stripping changed the loaded image for $1" >&2
		exit 1
	fi
	printf '%-28s %s\n' "$1" "$("$PREFIX"-size main.elf | tail -1)"
}

build perm-every  "-DBR_PERM_EVERY_ITER"
build unprotected-win "-DCT_UNPROTECTED=1 -DBR_PRIV_TLEN_U=23"
make clean >/dev/null

{
	echo "Firmware images accompanying the constant-time measurements."
	echo
	echo "perm-every  : protected, window table re-permuted on every window iteration"
	echo "unprotected-win : br_rsa_i31_private(), no blinding, no fault check, on"
	echo "              the plain CRT parameters recovered by host/unblind_keys.py,"
	echo "              given the same 23*U scratch budget as the protected entry"
	echo "              point, which lets it use a 4-bit sliding window"
	echo
	echo "Target      : STM32F405 (Cortex-M4F), core clock per clock_setup()"
	echo "Compiler    : $("$PREFIX"-gcc --version | head -1)"
	echo "Flags       : -O2 $BASE_DEFINES \\"
	echo "              [-DBR_PERM_EVERY_ITER | -DCT_UNPROTECTED=1 -DBR_PRIV_TLEN_U=23] \\"
	echo "              -mthumb -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16"
	echo "Source      : git $(git rev-parse --short HEAD)$(git diff --quiet -- . ":(exclude)$OUT" || echo ' + uncommitted changes')"
	echo "Built       : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo
	echo "Each image runs 100 keys x 4 message classes (m=0, m=1, m=n-1, m=random),"
	echo "then repeats three fixed (key, message) pairs 100 times each, reporting"
	echo "DWT_CYCCNT over the private-key operation for every run: the protected"
	echo "br_rsa_i31_private_blind_mod_key_FI, or br_rsa_i31_private in the"
	echo "baseline image."
	echo
	echo "ELF images are stripped of symbols, debug info and .comment; the"
	echo "loaded image is unaffected and each .bin is derived from its"
	echo "stripped ELF."
	echo
	echo "SHA-256:"
	sha256sum "$OUT"/*.elf "$OUT"/*.bin | sed "s|$OUT/|  |"
} > "$OUT/BUILDINFO.txt"

echo
cat "$OUT/BUILDINFO.txt"
