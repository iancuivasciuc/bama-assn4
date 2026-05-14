# Assignment 4
## Step 1
I created an initial 4096 bytes input file and gave it as input.

I instrumented all CMP and TEST instruction variations: (reg, reg), (reg, mem), (reg, imm), (mem, imm).

For each byte of the comparison, if one of the operands has taint on it, I save the compared value to a global array.

I added a Fini hook that writes what it finds to a new file.

### Notes
* only one byte can be tainted at a certain time

## Step 2
I looked at the dynamic symbols of the program and saw all the library functions that are being called.

I added hooks for:
* `memcpy`
* `__memcpy_chk`
* `memset`
* `memcmp`
* `strcmp`
* `strncmp`

## Step 3
Instead of clearing the taint for arithmetic instructions, now we propagate the taint on them.

### Notes
A 4-bytes register write clears the upper 4 bytes as well.

## Step 4
Initially, I added a stack of operations (`{opcode, value}`) for each byte of the input file and reversed them in the compare functions.

Later, I realized that the only a XOR is done for obfuscation. I added a global array with xor and use the values to xor the value find by the comparison instructions.

## Performance
I found this part quite challenging and fun. Every function is inlined, except the library calls hooks. To achieve this, I use a couple of techniques.

### Templates
Instead of using the size at runtime, we can use template functions that use the size as a parameter.

These functions know their size at compile time, so the compiler can perform more aggresive optimizations. They replace the loops, with fast SIMD instructions.

### \_\_restrict\_\_ keyword
The restrict keyword provides a guarantee for the compiler that the pointers received as functions arguments do not overlap. This helps the compiler to remove overlap branching logic.

### Transition to branchless logic
```
template<uint32_t N>
static void handle_xor_regtoreg(tag_t *__restrict__ dst, tag_t *__restrict__ src, ADDRINT dst_val, ADDRINT src_val) {
    for (uint32_t n = 0; n < N; n++) {
        g_xor[src[n]] = (dst_val >> (n * 8)) & 0xFF;
        g_xor[dst[n]] = (src_val >> (n * 8)) & 0xFF;
        dst[n] += src[n];
    }
    if (N == 4)
        std::memset(dst + 4, 0, sizeof(tag_t) * 4);
}
```

`XOR` is an instruction that propagates taint. The operation can be performened per byte. We use the observation that only one byte out of the two can have taint.

When `src[n] != 0` then `dst[n] == 0` and vice versa. This helps us go from:
```
if (src[n])
    dst[n] = src[n]
```

To:

```
dst[n] += src[n];
```

Additionally, the global arrays (`g_ident` and `g_xor`) are indexed from 1. So, if we have taint, we modified a real global value, but if there is no taint, we modify the 0-index value which is not used.

### Splitting the comparision per bytes
I am not sure if this approach is faster than the initial one, but I wanted to have every function inlined.

I moved the loop to the instrumentation function, and the hook only compares one byte at the time.

## Script
The script does the following:
* creates an initial identity file
* compiles the pintool
* calls the binary with the identity file

## Second secret
Not found!
