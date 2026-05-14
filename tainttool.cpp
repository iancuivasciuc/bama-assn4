#include "pin.H"
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <fstream>

/* Undefine these to get some feedback about what your pintool is doing. */
//#define PRINT_BASIC_BLOCKS /* show basic block addresses when instrumenting them */
// #define PRINT_ALL_INSTS /* print each instruction before instrumenting it*/
// #define PRINT_UNHANDLED_INSTS /* print instructions which are not instrumented */

KNOB<std::string> KnobInputFile(KNOB_MODE_WRITEONCE, "pintool", "i", "input.txt", "specify input file to be tainted");

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))
#define ROUND_DOWN(N, S) ((N / S) * S)

/* Get the size (in bytes) for a PIN register. */
inline uint32_t getRegSize(REG reg) {
	if (REG_is_zmm(reg))
		return 64;
	else if (REG_is_ymm(reg))
		return 32;
	else if (REG_is_xmm(reg))
		return 16;
	else if (REG_is_gr64(reg))
		return 8;
	else if (REG_is_gr32(reg))
		return 4;
	else if (REG_is_gr16(reg))
		return 2;
	else
		return 1;
}

/*
 * Offsets into our (per-byte) register taint buffer.
 * If you add new registers, make sure they don't overlap!
 */
enum taint_regs {
	TREG_RAX = 0*8,
	TREG_RBX = 1*8,
	TREG_RCX = 2*8,
	TREG_RDX = 3*8,
	TREG_RSI = 4*8,
	TREG_RDI = 5*8,
	TREG_RSP = 6*8,
	TREG_RBP = 7*8,
	TREG_RIP = 8*8,
	TREG_R8  = 9*8,
	TREG_R9  = 10*8,
	TREG_R10 = 11*8,
	TREG_R11 = 12*8,
	TREG_R12 = 13*8,
	TREG_R13 = 14*8,
	TREG_R14 = 15*8,
	TREG_R15 = 16*8,
	TREG_XMM0 = 17*8 + 0*16,
	TREG_XMM1 = 17*8 + 1*16,
	TREG_XMM2 = 17*8 + 2*16,
	TREG_XMM3 = 17*8 + 3*16,
	TREG_XMM4 = 17*8 + 4*16,
	TREG_XMM5 = 17*8 + 5*16,
	TREG_XMM6 = 17*8 + 6*16,
	TREG_XMM7 = 17*8 + 7*16,
	TREG_END = 17*8 + 16*32
};

/*
 * Get our internal register offset for a PIN register.
 * (These are used as byte offsets into the g_regTags array, below.)
 */
inline unsigned getTaintReg(REG reg) {
	switch (reg) {
	case REG_RAX:
	case REG_EAX:
	case REG_AX:
	case REG_AL:
		return TREG_RAX;
	case REG_AH:
		return TREG_RAX+1;
	case REG_RBX:
	case REG_EBX:
	case REG_BX:
	case REG_BL:
		return TREG_RBX;
	case REG_BH:
		return TREG_RBX+1;
	case REG_RCX:
	case REG_ECX:
	case REG_CX:
	case REG_CL:
		return TREG_RCX;
	case REG_CH:
		return TREG_RCX+1;
	case REG_RDX:
	case REG_EDX:
	case REG_DX:
	case REG_DL:
		return TREG_RDX;
	case REG_DH:
		return TREG_RDX+1;
	case REG_RSI:
	case REG_ESI:
	case REG_SI:
	case REG_SIL:
		return TREG_RSI;
	case REG_RDI:
	case REG_EDI:
	case REG_DI:
	case REG_DIL:
		return TREG_RDI;
	case REG_RSP:
	case REG_ESP:
	case REG_SP:
	case REG_SPL:
		return TREG_RSP;
	case REG_RBP:
	case REG_EBP:
	case REG_BP:
	case REG_BPL:
		return TREG_RBP;
	case REG_RIP:
	case REG_EIP:
	case REG_IP:
		return TREG_RIP;
	case REG_R8:
	case REG_R8B:
	case REG_R8W:
	case REG_R8D:
		return TREG_R8;
	case REG_R9:
	case REG_R9B:
	case REG_R9W:
	case REG_R9D:
		return TREG_R9;
	case REG_R10:
	case REG_R10B:
	case REG_R10W:
	case REG_R10D:
		return TREG_R10;
	case REG_R11:
	case REG_R11B:
	case REG_R11W:
	case REG_R11D:
		return TREG_R11;
	case REG_R12:
	case REG_R12B:
	case REG_R12W:
	case REG_R12D:
		return TREG_R12;
	case REG_R13:
	case REG_R13B:
	case REG_R13W:
	case REG_R13D:
		return TREG_R13;
	case REG_R14:
	case REG_R14B:
	case REG_R14W:
	case REG_R14D:
		return TREG_R14;
	case REG_R15:
	case REG_R15B:
	case REG_R15W:
	case REG_R15D:
		return TREG_R15;
	/*
	 * A minimal set of XMM registers; should be enough for the BAMA binary itself.
	 * If you want to instrument your system libraries, you might need more..
	 */
	case REG_XMM0: return TREG_XMM0;
	case REG_XMM1: return TREG_XMM1;
	case REG_XMM2: return TREG_XMM2;
	case REG_XMM3: return TREG_XMM3;
	case REG_XMM4: return TREG_XMM4;
	case REG_XMM5: return TREG_XMM5;
	case REG_XMM6: return TREG_XMM6;
	case REG_XMM7: return TREG_XMM7;
	default:
		printf("unsupported PIN register %d\n", reg);
		exit(1);
	}
}

#define IDENTITY_FILE_SIZE 4097

typedef uint16_t tag_t;

/* Given an address, return the corresponding shadow memory (where we'll store the taint tags). */
__attribute__((always_inline)) inline tag_t *addrToShadow(const void *addr) {
	return (tag_t *)((((uint64_t)(addr) + 0x200000000000ull) << 1) & 0x7fffffffffffull);
}

tag_t g_regTags[TREG_END];
char g_ident[IDENTITY_FILE_SIZE];
char g_xor[IDENTITY_FILE_SIZE] = {};

/* Standard library hooks */
void before_memset(char *dest, int c, size_t n) {
    tag_t *shadow = addrToShadow(dest);
    for (unsigned i = 0; i < n; ++i)
        shadow[i] = g_regTags[getTaintReg(REG_SIL)];
}

void before_memcpy(char *dest, const char *src, size_t n) {
    tag_t *srcShadow = addrToShadow(src);
    tag_t *destShadow = addrToShadow(dest);
    for (unsigned i = 0; i < n; ++i)
        destShadow[i] = srcShadow[i];
}

void before_memcmp(const char *s1, const char *s2, size_t n) {
    tag_t *s1Shadow = addrToShadow(s1);
    tag_t *s2Shadow = addrToShadow(s2);
    for (unsigned i = 0; i < n; ++i) {
        g_ident[s1Shadow[i]] = s2[i] ^ g_xor[s1Shadow[i]]; 
        g_ident[s2Shadow[i]] = s1[i] ^ g_xor[s2Shadow[i]];
    }
}

void before_strcmp(const char *s1, const char *s2) {
    tag_t *s1Shadow = addrToShadow(s1);
    tag_t *s2Shadow = addrToShadow(s2);

    unsigned i = 0;
    for (;;) {
        g_ident[s1Shadow[i]] = s2[i] ^ g_xor[s1Shadow[i]]; 
        g_ident[s2Shadow[i]] = s1[i] ^ g_xor[s2Shadow[i]];

        if (s1[i] == '\0' || s2[i] == '\0')
            break;

        i++;
    }
}

void before_strncmp(const char *s1, const char *s2, size_t n) {
    tag_t *s1Shadow = addrToShadow(s1);
    tag_t *s2Shadow = addrToShadow(s2);

    for (unsigned i = 0; i < n; ++i) {
        g_ident[s1Shadow[i]] = s2[i] ^ g_xor[s1Shadow[i]]; 
        g_ident[s2Shadow[i]] = s1[i] ^ g_xor[s2Shadow[i]];

        if (s1[i] == '\0' || s2[i] == '\0')
            break;
    }
}

/* PIN calls this when a new image (binary/library) is loaded */
void ImageLoad(IMG img, void *) {
	if (!IMG_IsMainExecutable(img))
	       return;

	RTN rtn = RTN_FindByName(img, "memset");
	if (RTN_Valid(rtn)) {
	    RTN_Open(rtn);
	    RTN_InsertCall(rtn, IPOINT_BEFORE,
	            (AFUNPTR)before_memset,
	            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
	            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
	            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
	            IARG_END);
	    RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "__memset_chk");
	   if (RTN_Valid(rtn)) {
	       RTN_Open(rtn);
	       RTN_InsertCall(rtn, IPOINT_BEFORE,
	               (AFUNPTR)before_memset,
	               IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
	               IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
	               IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
	               IARG_END);
	       RTN_Close(rtn);
	   }

	rtn = RTN_FindByName(img, "memcpy");
	   if (RTN_Valid(rtn)) {
	       RTN_Open(rtn);
	       RTN_InsertCall(rtn, IPOINT_BEFORE,
	               (AFUNPTR)before_memcpy,
	               IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
	               IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
	               IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
	               IARG_END);
	       RTN_Close(rtn);
	   }

	rtn = RTN_FindByName(img, "memcmp");
	   if (RTN_Valid(rtn)) {
	       RTN_Open(rtn);
	       RTN_InsertCall(rtn, IPOINT_BEFORE,
	               (AFUNPTR)before_memcmp,
	               IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
	               IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
	               IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
	               IARG_END);
	       RTN_Close(rtn);
	   }

	rtn = RTN_FindByName(img, "strcmp");
	if (RTN_Valid(rtn)) {
	    RTN_Open(rtn);
	    RTN_InsertCall(rtn, IPOINT_BEFORE,
	            (AFUNPTR)before_strcmp,
	            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
	            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
	            IARG_END);
	    RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "strncmp");
	if (RTN_Valid(rtn)) {
	    RTN_Open(rtn);
	    RTN_InsertCall(rtn, IPOINT_BEFORE,
	            (AFUNPTR)before_strncmp,
	            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
	            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
	            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
	            IARG_END);
	    RTN_Close(rtn);
	}
}


/* ---------- Instruction handlers ---------- */
#define GET_HANDLER(func, size) \
    ((size) == 1 ? (AFUNPTR)(func<1>) : \
     (size) == 2 ? (AFUNPTR)(func<2>) : \
     (size) == 4 ? (AFUNPTR)(func<4>) : \
     (size) == 8 ? (AFUNPTR)(func<8>) : NULL)

/* ---------- Clear handlers ---------- */
template<uint32_t N>
static void handle_clear_reg(tag_t *dst) {
    std::memset(dst, 0, sizeof(tag_t) * N);
    if (N == 4)
        std::memset(dst + 4, 0, sizeof(tag_t) * 4);
}

template<uint32_t N>
static void handle_clear_mem(char *dst) {
    tag_t *shadow = addrToShadow(dst);
    std::memset(shadow, 0, sizeof(tag_t) * N);
}

static void handle_clear(INS ins) {
    if (INS_OperandIsReg(ins, 0)) {
        AFUNPTR handler = GET_HANDLER(handle_clear_reg, getRegSize(INS_OperandReg(ins, 0)));
        if (!handler)
            return;

        INS_InsertCall(ins, IPOINT_BEFORE,
                handler,
                IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
                IARG_END);
        return;
    }

    AFUNPTR handler = GET_HANDLER(handle_clear_mem, (INS_OperandWidth(ins, 0) / 8));
    INS_InsertCall(ins, IPOINT_BEFORE,
            handler,
            IARG_MEMORYWRITE_EA,
            IARG_END);
}

/* ---------- Move handlers ---------- */
template<uint32_t N>
static void handle_mov_memtomem(char *dst, char *src) {
	tag_t *shadowDst = addrToShadow(dst);
	tag_t *shadowSrc = addrToShadow(src);
    std::memcpy(shadowDst, shadowSrc, sizeof(tag_t) * N);
}

template<uint32_t N>
static void handle_mov_memtoreg(tag_t *dst, char *src) {
	tag_t *shadow = addrToShadow(src);
    std::memcpy(dst, shadow, sizeof(tag_t) * N);
	if (N == 4)
        std::memset(dst + 4, 0, sizeof(tag_t) * 4);
}

template<uint32_t N>
static void handle_mov_regtomem(char *dst, tag_t *src) {
	tag_t *shadow = addrToShadow(dst);
    std::memcpy(shadow, src, sizeof(tag_t) * N);
}

template<uint32_t N>
static void handle_mov_regtoreg(tag_t *dst, tag_t *src) {
    std::memcpy(dst, src, sizeof(tag_t) * N);
    if (N == 4)
        std::memset(dst + 4, 0, sizeof(tag_t) * 4);
}

static void handle_mov(INS ins) {
    if (INS_OperandIsImmediate(ins, 1)) {
        handle_clear(ins);
        return;
    }

    if (INS_OperandIsMemory(ins, 1)) {
        AFUNPTR handler = GET_HANDLER(handle_mov_memtoreg, INS_OperandWidth(ins, 1) / 8);
        INS_InsertCall(ins, IPOINT_BEFORE,
                handler,
                IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
                IARG_MEMORYREAD_EA,
                IARG_END);
        return;
    }

    uint32_t size = getRegSize(INS_OperandReg(ins, 1));

    if (INS_OperandIsMemory(ins, 0)) {
        AFUNPTR handler = GET_HANDLER(handle_mov_regtomem, size);
        if (!handler)
            return;

        INS_InsertCall(ins, IPOINT_BEFORE,
                handler,
                IARG_MEMORYWRITE_EA,
                IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 1))],
                IARG_END);
        return;
    }

    AFUNPTR handler = GET_HANDLER(handle_mov_regtoreg, size);
    if (!handler)
        return;

    INS_InsertCall(ins, IPOINT_BEFORE,
            handler,
            IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
            IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 1))],
            IARG_END);
}

/* ---------- Move with zero extension handlers ---------- */
#define GET_MOVZX_HANDLER(func, dst_size, src_size) \
    ((dst_size) == 2 && (src_size) == 1 ? (AFUNPTR)(func<2, 1>) : \
     (dst_size) == 4 && (src_size) == 1 ? (AFUNPTR)(func<4, 1>) : \
     (dst_size) == 4 && (src_size) == 2 ? (AFUNPTR)(func<4, 2>) : \
     (dst_size) == 8 && (src_size) == 1 ? (AFUNPTR)(func<8, 1>) : \
     (dst_size) == 8 && (src_size) == 2 ? (AFUNPTR)(func<8, 2>) : NULL);

template <uint32_t DST_N, uint32_t SRC_N>
static void handle_movzx_regtoreg(tag_t *dst, tag_t *src) {
    for (uint32_t n = 0; n < SRC_N; n++)
        dst[n] = src[n];
    for (uint32_t n = SRC_N; n < DST_N; n++)
        dst[n] = 0;
}

template <uint32_t DST_N, uint32_t SRC_N>
static void handle_movzx_memtoreg(tag_t *dst, char *src) {
    tag_t *shadow = addrToShadow(src);
    for (uint32_t n = 0; n < SRC_N; n++)
        dst[n] = shadow[n];
    for (uint32_t n = SRC_N; n < DST_N; n++)
        dst[n] = 0;
}

static void handle_movzx(INS ins) {
    uint32_t dst_size = getRegSize(INS_OperandReg(ins, 0));

    if (INS_OperandIsReg(ins, 1)) {
        AFUNPTR handler = GET_MOVZX_HANDLER(handle_movzx_regtoreg, dst_size, getRegSize(INS_OperandReg(ins, 1)));
        if (!handler)
            return;

        INS_InsertCall(ins, IPOINT_BEFORE,
                handler,
                IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
                IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 1))],
                IARG_END);
        return;
    }

    AFUNPTR handler = GET_MOVZX_HANDLER(handle_movzx_memtoreg, dst_size, getRegSize(INS_OperandReg(ins, 1)));
    if (!handler)
        return;

    INS_InsertCall(ins, IPOINT_BEFORE,
            handler,
            IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
            IARG_MEMORYREAD_EA,
            IARG_END);
}

/* ---------- Compare handlers ---------- */
static void handle_cmp_regtoreg(tag_t *__restrict__ tag1, tag_t *__restrict__ tag2, ADDRINT val1, ADDRINT val2, uint32_t shift) {
    g_ident[*tag1] = ((val2 >> shift) & 0xFF) ^ g_xor[*tag1];
    g_ident[*tag2] = ((val1 >> shift) & 0xFF) ^ g_xor[*tag2];
}

static void handle_cmp_memtoreg(tag_t *__restrict__ tag, char *__restrict__ addr, ADDRINT reg_val, uint32_t shift) {
    tag_t *shadow = addrToShadow(addr);
    g_ident[*tag] = addr[shift / 8] ^ g_xor[*tag];
    g_ident[shadow[shift / 8]] = ((reg_val >> shift) & 0xFF) ^ g_xor[shadow[shift / 8]];
}

static void handle_cmp_immtoreg(tag_t *tag, uint8_t imm) {
    g_ident[*tag] = imm ^ g_xor[*tag];
}

static void handle_cmp_immtomem(char *addr, uint8_t imm, uint32_t shift) {
    tag_t *shadow = addrToShadow(addr);
    g_ident[shadow[shift / 8]] = imm ^ g_xor[shadow[shift / 8]];
}

static void handle_cmp(INS ins) {
    if (INS_OperandIsReg(ins, 0)) {
        uint32_t size = getRegSize(INS_OperandReg(ins, 0));

        if (INS_OperandIsReg(ins, 1)) {
            for (uint32_t n = 0; n < size; n++) {
                INS_InsertCall(ins, IPOINT_BEFORE,
                        (AFUNPTR)handle_cmp_regtoreg,
                        IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
                        IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 1))],
                        IARG_REG_VALUE, INS_OperandReg(ins, 0),
                        IARG_REG_VALUE, INS_OperandReg(ins, 1),
                        IARG_UINT32, n * 8,
                        IARG_END);
            }
            return;
        }

        if (INS_OperandIsMemory(ins, 1)) {
            for (uint32_t n = 0; n < size; n++) {
                INS_InsertCall(ins, IPOINT_BEFORE,
                        (AFUNPTR)handle_cmp_memtoreg,
                        IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
                        IARG_MEMORYREAD_EA,
                        IARG_REG_VALUE, INS_OperandReg(ins, 0),
                        IARG_UINT32, n * 8,
                        IARG_END);
            }
            return;
        }

        for (uint32_t n = 0; n < size; n++) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_cmp_immtoreg,
                    IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
                    IARG_UINT32, (INS_OperandImmediate(ins, 1) >> (n * 8)) & 0xFF,
                    IARG_END);
            return;
        }
    }

    uint32_t size = INS_OperandWidth(ins, 0) / 8;

    if (INS_OperandIsReg(ins, 1)) {
        for (uint32_t n = 0; n < size; n++) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_cmp_memtoreg,
                    IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 1))],
                    IARG_MEMORYREAD_EA,
                    IARG_REG_VALUE, INS_OperandReg(ins, 1),
                    IARG_UINT32, n * 8,
                    IARG_END);
        }
        return;
    }

    for (uint32_t n = 0; n < size; n++) {
        INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)handle_cmp_immtomem,
                IARG_MEMORYREAD_EA,
                IARG_UINT32, (INS_OperandImmediate(ins, 1) >> (n * 8)) & 0xFF,
                IARG_UINT32, n * 8,
                IARG_END);
    }
}

/* ---------- Compare handlers ---------- */
template<uint32_t N>
static void handle_arith_regtoreg(tag_t *__restrict__ dst, tag_t *__restrict__ src) {
    for (uint32_t n = 0; n < N; ++n)
        dst[n] += src[n];
    if (N == 4)
        std::memset(dst + 4, 0, sizeof(tag_t) * 4);
}

template<uint32_t N>
static void handle_arith_memtoreg(tag_t *__restrict__ dst, char *__restrict__ src) {
    tag_t *shadow = addrToShadow(src);
    for (uint32_t n = 0; n < N; ++n)
        dst[n] += shadow[n];
    if (N == 4)
        std::memset(dst + 4, 0, 4);
}

template<uint32_t N>
static void handle_arith_immtoreg(tag_t *__restrict__ dst) {
    if (N == 4)
        std::memset(dst + 4, 0, 4);
}

template<uint32_t N>
static void handle_arith_regtomem(char *__restrict__ dst, tag_t *__restrict__ src) {
    tag_t *shadow = addrToShadow(dst);
    for (uint32_t n = 0; n < N; ++n)
        shadow[n] += src[n];
}

static void handle_arith(INS ins) {
    uint32_t size = INS_OperandWidth(ins, 0) / 8;

    if (INS_OperandIsMemory(ins, 0)) {
        if (INS_OperandIsReg(ins, 1)) {
            AFUNPTR handler = GET_HANDLER(handle_arith_regtomem, size);
            if (!handler)
                return;

            INS_InsertCall(ins, IPOINT_BEFORE,
                    handler,
                    IARG_MEMORYWRITE_EA,
                    IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 1))],
                    IARG_END);
        }
        return;
    }

    if (INS_OperandIsMemory(ins, 1)) {
        AFUNPTR handler = GET_HANDLER(handle_arith_memtoreg, size);
        if (!handler)
            return;

        INS_InsertCall(ins, IPOINT_BEFORE,
                handler,
                IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
                IARG_MEMORYREAD_EA,
                IARG_END);
        return;
    }

    if (INS_OperandIsImmediate(ins, 1) || (INS_OperandReg(ins, 0) == INS_OperandReg(ins, 1))) {
        AFUNPTR handler = GET_HANDLER(handle_arith_immtoreg, size);
        if (!handler)
            return;

        INS_InsertCall(ins, IPOINT_BEFORE,
                handler,
                IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
                IARG_END);
        return;
    }

    AFUNPTR handler = GET_HANDLER(handle_arith_regtoreg, size);
    if (!handler)
        return;

    INS_InsertCall(ins, IPOINT_BEFORE,
            handler,
            IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
            IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 1))],
            IARG_END);
}

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

template<uint32_t N>
static void handle_xor_memtoreg(tag_t *__restrict__ dst, char *__restrict__ src, ADDRINT dst_val) {
    tag_t *shadow = addrToShadow(src);
    for (uint32_t n = 0; n < N; n++) {
        g_xor[shadow[n]] = (dst_val >> (n * 8)) & 0xFF;
        g_xor[dst[n]] = src[n];
        dst[n] += shadow[n];
    }
    if (N == 4)
        std::memset(dst + 4, 0, sizeof(tag_t) * 4);
}

template<uint32_t N>
static void handle_xor_regtomem(char *__restrict__ dst, tag_t *__restrict__ src, ADDRINT src_val) {
    tag_t *shadow = addrToShadow(dst);
    for (uint32_t n = 0; n < N; n++) {
        g_xor[src[n]] = dst[n];
        g_xor[shadow[n]] = (src_val >> (n * 8)) & 0xFF;
        shadow[n] += src[n];
    }
}

static void handle_xor(INS ins) {
    uint32_t size = INS_OperandWidth(ins, 0) / 8;

    if (INS_OperandIsMemory(ins, 0)) {
        AFUNPTR handler = GET_HANDLER(handle_xor_regtomem, size);
        if (!handler)
            return;

        INS_InsertCall(ins, IPOINT_BEFORE,
                handler,
                IARG_MEMORYWRITE_EA,
                IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 1))],
                IARG_REG_VALUE, INS_OperandReg(ins, 1),
                IARG_END);
        return;
    }

    if (INS_OperandIsMemory(ins, 1)) {
        AFUNPTR handler = GET_HANDLER(handle_xor_memtoreg, size);
        if (!handler)
            return;

        INS_InsertCall(ins, IPOINT_BEFORE,
                handler,
                IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
                IARG_MEMORYREAD_EA,
                IARG_REG_VALUE, INS_OperandReg(ins, 0),
                IARG_END);
        return;
    }

    if (INS_OperandReg(ins, 0) == INS_OperandReg(ins, 1)) {
        handle_clear(ins);
        return;
    }

    AFUNPTR handler = GET_HANDLER(handle_xor_regtoreg, size);
    if (!handler)
        return;

    INS_InsertCall(ins, IPOINT_BEFORE,
            handler,
            IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
            IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 1))],
            IARG_REG_VALUE, INS_OperandReg(ins, 0),
            IARG_REG_VALUE, INS_OperandReg(ins, 1),
            IARG_END);
}

static void handle_push(INS ins) {
    if (INS_OperandIsImmediate(ins, 0)) {
        INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)handle_clear_mem<8>,
                IARG_MEMORYWRITE_EA,
                IARG_END);
        return;
    }

    if (INS_OperandIsReg(ins, 0)) {
        AFUNPTR handler = GET_HANDLER(handle_mov_regtomem, getRegSize(INS_OperandReg(ins, 0)));
        if (!handler)
            return;

        INS_InsertCall(ins, IPOINT_BEFORE,
                handler,
                IARG_MEMORYWRITE_EA,
                IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
                IARG_END);
        return;
    }

    AFUNPTR handler = GET_HANDLER(handle_mov_memtomem, INS_OperandWidth(ins, 0) / 8);
    INS_InsertCall(ins, IPOINT_BEFORE,
            handler,
            IARG_MEMORYWRITE_EA,
            IARG_MEMORYREAD_EA,
            IARG_END);
}

static void handle_pop(INS ins) {
    if (INS_OperandIsReg(ins, 0)) {
        AFUNPTR handler = GET_HANDLER(handle_mov_memtoreg, getRegSize(INS_OperandReg(ins, 0)));
        if (!handler)
            return;

        INS_InsertCall(ins, IPOINT_BEFORE,
                handler,
                IARG_PTR, &g_regTags[getTaintReg(INS_OperandReg(ins, 0))],
                IARG_MEMORYREAD_EA,
                IARG_END);
        return;
    }

    AFUNPTR handler = GET_HANDLER(handle_mov_memtomem, INS_OperandWidth(ins, 0) / 8);
    INS_InsertCall(ins, IPOINT_BEFORE,
            handler,
            IARG_MEMORYWRITE_EA,
            IARG_MEMORYREAD_EA,
            IARG_END);
}

/* PIN calls this while translating an instruction */
void Instrument(INS ins, void *) {
	xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);

#ifdef PRINT_ALL_INSTS
	printf("instrumenting@%p: %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
#endif

    switch (ins_opcode) {
        case XED_ICLASS_CMP:
        case XED_ICLASS_TEST:
            handle_cmp(ins);
            break;
        case XED_ICLASS_XOR:
            handle_xor(ins);
            break;
        case XED_ICLASS_ADD:
        case XED_ICLASS_SUB:
        case XED_ICLASS_AND:
        case XED_ICLASS_OR:
            handle_arith(ins);
            break;
        case XED_ICLASS_MOV:
            /* We implemented MOV for you (except one bit in a helper function, above, for you to fill in). */
            handle_mov(ins);
            break;
        case XED_ICLASS_MOVSX:
        case XED_ICLASS_MOVSXD:
            /*
             * We implement MOVSX/MOVSXD the same as MOVZX (clearing taint).
             * This is incorrect but should be enough for this assignment.
             */
        case XED_ICLASS_MOVZX:
            handle_movzx(ins);
            break;
        case XED_ICLASS_MOVBE:
        case XED_ICLASS_MOVQ:
        case XED_ICLASS_MOVD:
        case XED_ICLASS_VMOVQ:
        case XED_ICLASS_VMOVD:
        case XED_ICLASS_VMOVAPD:
        case XED_ICLASS_MOVSD:
        case XED_ICLASS_MOVSD_XMM:
        case XED_ICLASS_VMOVSD:
        case XED_ICLASS_MOVDQU:
        case XED_ICLASS_MOVDQA:
        case XED_ICLASS_VMOVDQU:
        case XED_ICLASS_VMOVDQA:
        case XED_ICLASS_MOVUPS:
        case XED_ICLASS_MOVAPS:
        case XED_ICLASS_MOVAPD:
        case XED_ICLASS_VMOVAPS:
        case XED_ICLASS_MOVLPD:
        case XED_ICLASS_MOVHPD:
        case XED_ICLASS_MOVLPS:
        case XED_ICLASS_MOVHPS:
        case XED_ICLASS_XCHG:
        case XED_ICLASS_BSWAP:
        case XED_ICLASS_LEA:
            // This just clears taint on the target, which should suffice for BAMA.
            handle_clear(ins);
            break;
        case XED_ICLASS_PUSH:
            handle_push(ins);
            break;
        case XED_ICLASS_POP:
            handle_pop(ins);
            break;
        default:
#ifdef PRINT_UNHANDLED_INSTS
            printf("unhandled @%p: %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
#endif
            break;
    }
}

std::map<int, std::string> g_open_fds;

/* post-event callback for open/openat() system calls (called by syscall_exit) */
void open_hook(const char *filename, int fd) {
	if (fd == -1)
		return;

	/* Keep track of file descriptors, for use in read_hook, below. */
	g_open_fds[fd] = std::string(filename);
}

/* post-event callback for read() system call (called by syscall_exit) */
void read_hook(int fd, char *buf, size_t count) {
	if (count == (size_t)-1)
		return;

	/* Only taint the file we're interested in. */
	if (g_open_fds[fd] != KnobInputFile.Value())
		return;

	size_t pos = lseek(fd, 0, SEEK_CUR) - count; /* [current pos] - [bytes read] = start pos */
	for (uint n = 0; n < count; ++n) {
		/*
		 * This is where we taint the input. Specifically, for file offset n,
		 * we set the shadow memory for the buffer to tag (color) n+1.
		 */
		*(addrToShadow(buf + n)) = pos + n + 1;

        /* Copy the initial identity file to g_ident. */
        g_ident[n + 1] = buf[n];
	}
}

/*
 * Some context which we store in syscall_entry, because we need it in syscall_exit.
 * (!) To support threads, you'd have to store this in thread local storage (see PIN's TLS helper functions).
 */
static uint64_t g_last_syscall;
static uint64_t g_last_context[4];

/* PIN calls this just before a system call */
void syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
	g_last_syscall = PIN_GetSyscallNumber(ctx, std);
	for (unsigned n = 0; n < 4; ++n)
		g_last_context[n] = PIN_GetSyscallArgument(ctx, std, n);
}

/* PIN calls this just after a system call */
void syscall_exit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
	uint64_t ret = PIN_GetSyscallReturn(ctx, std);
	switch (g_last_syscall) {
	case SYS_open:
		open_hook((char *)g_last_context[0], ret);
		break;
	case SYS_openat:
		open_hook((char *)g_last_context[1], ret);
		break;
	case SYS_read:
		read_hook(g_last_context[0], (char *)g_last_context[1], ret);
		break;
	default:
		break;
	}
}

void Trace(TRACE trace, void *) {
	/* Iterate through the basic blocks which PIN wants to instrument right now. */
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		/*
		 * The system libraries use many more instructions than the BAMA binary does.
		 * We suggest that you exclude libraries from instrumentation (with the code below).
		 * and implement tainting by instrumenting the individual library calls instead.
		 */
		IMG img = IMG_FindByAddress(BBL_Address(bbl));
		if (!IMG_Valid(img) || !IMG_IsMainExecutable(img))
			continue;

#ifdef PRINT_BASIC_BLOCKS
		printf("Instrumenting basic block at %p\n", BBL_Address(bbl));
#endif

		/* Instrument every instruction in this basic block. */
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
			Instrument(ins, 0);
		}
	}
}

void Fini(INT32 code, void *) {
    std::ofstream out("input_secret.txt", std::ios::binary);
    out.write((const char*)&g_ident[1], IDENTITY_FILE_SIZE);
    out.close();

    int count = 0;
    for (unsigned n = 1; n < IDENTITY_FILE_SIZE; ++n) {
        if (g_ident[n] != 'X') {
            count++;
        }
        printf("%c", g_ident[n]);
    }
    printf("\nFound bytes: %d!\n", count);
}

int main (int argc, char *argv[]) {
	/* This makes PIN handle IFuncs; RTN_FindByName gives us implementations in modern PIN, so we can pretend they don't exist. */
	PIN_InitSymbolsAlt(IFUNC_SYMBOLS);
	if (PIN_Init(argc, argv))
		return 1;

	/* Map most of the address space for use as shadow memory, which we'll use to store taint tags. */
	int mmap_prot = PROT_READ | PROT_WRITE;
	int mmap_flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE;
	if (mmap((void *)0x100000000000ull, 0x600000000000ull, mmap_prot, mmap_flags, -1, 0) == (void *)-1) {
		const char *err = strerror(errno);
		PIN_ERROR(std::string("Failed to mmap shadow region: ") + err + std::string("\n"));
		return 1;
	}

	/* We want to instrument instructions. */
	TRACE_AddInstrumentFunction(Trace, 0);
	/* We want to hook functions when new images (binaries/libraries) are loaded. */
	IMG_AddInstrumentFunction(ImageLoad, 0);
	/* We want to be called when system calls are made. */
	PIN_AddSyscallEntryFunction(&syscall_entry, NULL);
	PIN_AddSyscallExitFunction(&syscall_exit, NULL);
    PIN_AddFiniFunction(Fini, 0);

	/* Let's go! */
	PIN_StartProgram();
}

