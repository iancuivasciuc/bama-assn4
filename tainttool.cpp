#include "pin.H"
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <fstream>
/* Undefine these to get some feedback about what your pintool is doing. */
//#define PRINT_BASIC_BLOCKS /* show basic block addresses when instrumenting them */
// #define PRINT_ALL_INSTS /* print each instruction before instrumenting it*/
//#define PRINT_UNHANDLED_INSTS /* print instructions which are not instrumented */

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

#define IDENTITY_FILE_SIZE 4096

typedef uint16_t tag_t;

/* Given an address, return the corresponding shadow memory (where we'll store the taint tags). */
inline tag_t *addrToShadow(const void *addr) {
	return (tag_t *)((((uint64_t)(addr) + 0x200000000000ull) << 1) & 0x7fffffffffffull);
}

tag_t g_regTags[TREG_END];
char g_ident[IDENTITY_FILE_SIZE];

/* Standard library hooks */
void before_memset(char *dest, int c, size_t n) {
    tag_t *shadow = addrToShadow(dest);

    for (unsigned i = 0; i < n; ++i)
        shadow[i] = g_regTags[REG_SIL];
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
        if (s1Shadow[i] > 0)
            g_ident[s1Shadow[i] - 1] = s2[i]; 
        if (s2Shadow[i] > 0)
            g_ident[s2Shadow[i] - 1] = s1[i];
    }
}

void before_strcmp(const char *s1, const char *s2) {
    tag_t *s1Shadow = addrToShadow(s1);
    tag_t *s2Shadow = addrToShadow(s2);

    unsigned i = 0;
    for (;;) {
        if (s1Shadow[i] > 0)
            g_ident[s1Shadow[i] - 1] = s2[i]; 
        if (s2Shadow[i] > 0)
            g_ident[s2Shadow[i] - 1] = s1[i];

        if (s1[i] == '\0' || s2[i] == '\0')
            break;

        i++;
    }
}

void before_strncmp(const char *s1, const char *s2, size_t n) {
    tag_t *s1Shadow = addrToShadow(s1);
    tag_t *s2Shadow = addrToShadow(s2);

    for (unsigned i = 0; i < n; ++i) {
        if (s1Shadow[i] > 0)
            g_ident[s1Shadow[i] - 1] = s2[i]; 
        if (s2Shadow[i] > 0)
            g_ident[s2Shadow[i] - 1] = s1[i];

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

/* Clear handlers */
static void handle_clear_mem(unsigned N, char *addr) {
	tag_t *shadow = addrToShadow(addr);

	for (unsigned n = 0; n < N; ++n)
		shadow[n] = 0;
}

static void handle_clear_reg(unsigned N, unsigned reg) {
	for (unsigned n = 0; n < N; ++n)
		g_regTags[reg + n] = 0;

	if (N == 4)
		for (unsigned n = 4; n < 8; ++n)
			g_regTags[reg + n] = 0;
}

/* Move handlers */
static void handle_mov_memtomem(unsigned N, char *to, char *from) {
	tag_t *shadowTo = addrToShadow(to);
	tag_t *shadowFrom = addrToShadow(from);

	for (unsigned n = 0; n < N; ++n)
        shadowTo[n] = shadowFrom[n];
}

static void handle_mov_memtoreg(unsigned N, char *addr, unsigned reg) {
	tag_t *shadow = addrToShadow(addr);

	for (unsigned n = 0; n < N; ++n)
		g_regTags[reg + n] = shadow[n];

	/* 32-bit register write, clear upper 64 bits */
	if (N == 4)
		for (unsigned n = 4; n < 8; ++n)
			g_regTags[reg + n] = 0;
}

static void handle_mov_regtomem(unsigned N, char *addr, uint64_t reg) {
	tag_t *shadow = addrToShadow(addr);

	for (unsigned n = 0; n < N; ++n)
        shadow[n] = g_regTags[reg + n];
}

static void handle_mov_regtoreg(unsigned N, uint64_t to, uint64_t from) {
	for (unsigned n = 0; n < N; ++n)
		g_regTags[to + n] = g_regTags[from + n];

	/* 32-bit register write, clear upper 64 bits */
	if (N == 4)
		for (unsigned n = 4; n < 8; ++n)
			g_regTags[to + n] = 0;
}

static void handle_mov(INS ins) {
    if (INS_OperandIsMemory(ins, 1)) {
        INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)handle_mov_memtoreg,
                IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
                IARG_MEMORYREAD_EA,
                IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
                IARG_END);
    } else if (INS_OperandIsImmediate(ins, 1)) {
        if (INS_OperandIsMemory(ins, 0)) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_clear_mem,
                    IARG_UINT32, INS_OperandWidth(ins, 0)/8,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
        } else {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_clear_reg,
                    IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
                    IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
                    IARG_END);
        }
    } else if (INS_OperandIsMemory(ins, 0)) {
        INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)handle_mov_regtomem,
                IARG_UINT32, INS_OperandWidth(ins, 0)/8,
                IARG_MEMORYWRITE_EA,
                IARG_UINT32, getTaintReg(INS_OperandReg(ins, 1)),
                IARG_END);
    } else {
        INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)handle_mov_regtoreg,
                IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
                IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
                IARG_UINT32, getTaintReg(INS_OperandReg(ins, 1)),
                IARG_END);
    }
}

static void handle_movzx_memtoreg(unsigned N, char *addr, uint64_t reg, uint32_t srcbytes) {
	tag_t *shadow = addrToShadow(addr);

	for (unsigned n = 0; n < srcbytes; ++n)
		g_regTags[reg + n] = shadow[n];
	for (unsigned n = srcbytes; n < N; ++n)
		g_regTags[reg + n] = 0;

	/* 32-bit register write, clear upper 64 bits */
	if (N == 4)
		for (unsigned n = 4; n < 8; ++n)
			g_regTags[reg + n] = 0;
}

static void handle_movzx_regtoreg(unsigned N, uint64_t to, uint64_t from, uint32_t srcbytes) {
	for (unsigned n = 0; n < srcbytes; ++n)
		g_regTags[to + n] = g_regTags[from + n];
	for (unsigned n = srcbytes; n < N; ++n)
		g_regTags[to + n] = 0;

	/* 32-bit register write, clear upper 64 bits */
	if (N == 4)
		for (unsigned n = 4; n < 8; ++n)
			g_regTags[to + n] = 0;
}

static void handle_movzx(INS ins) {
    if (INS_OperandIsMemory(ins, 1)) {
        INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)handle_movzx_memtoreg,
                IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
                IARG_MEMORYREAD_EA,
                IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
                IARG_UINT32, INS_OperandWidth(ins, 1)/8,
                IARG_END);
    } else {
        INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)handle_movzx_regtoreg,
                IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
                IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
                IARG_UINT32, getTaintReg(INS_OperandReg(ins, 1)),
                IARG_UINT32, INS_OperandWidth(ins, 1)/8,
                IARG_END);
    }
}

/* Compare handlers */
static void handle_cmp_regtoreg(unsigned N, uint32_t reg1, uint32_t reg2, ADDRINT val1, ADDRINT val2) {
    for (unsigned n = 0; n < N; ++n) {
        tag_t tag1 = g_regTags[reg1 + n];
        tag_t tag2 = g_regTags[reg2 + n];

        if (tag1 && tag2) {
            printf("I don't think this can happen!\n");
            return;
        }

        if (tag1)
            g_ident[tag1 - 1] = (val2 >> (n * 8)) & 0xFF;

        if (tag2)
            g_ident[tag2 - 1] = (val1 >> (n * 8)) & 0xFF;
    }
}

static void handle_cmp_memtoreg(unsigned N, uint32_t reg, char *addr, ADDRINT reg_val) {
    tag_t *shadow = addrToShadow(addr);

    for (unsigned n = 0; n < N; ++n) {
        tag_t tag = g_regTags[reg + n];

        if (tag)
            g_ident[tag - 1] = addr[n];

        if (shadow[n])
            g_ident[shadow[n] - 1] = (reg_val >> (n * 8)) & 0xFF;
    }
}

static void handle_cmp_immtoreg(unsigned N, uint32_t reg, uint64_t imm) {
    for (unsigned n = 0; n < N; ++n) {
        tag_t tag = g_regTags[reg + n];

        if (tag)
            g_ident[tag - 1] = (imm >> (n * 8)) & 0xFF;
    }
}

static void handle_cmp_immtomem(unsigned N, char *addr, uint64_t imm) {
    tag_t *shadow = addrToShadow(addr);

    for (unsigned n = 0; n < N; ++n) {
        if (shadow[n])
            g_ident[shadow[n] - 1] = (imm >> (n * 8)) & 0xFF;
    }
}

static void handle_cmp(INS ins) {
    if (INS_OperandIsReg(ins, 0)) {
        if (INS_OperandIsReg(ins, 1)) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_cmp_regtoreg,
                    IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
                    IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
                    IARG_UINT32, getTaintReg(INS_OperandReg(ins, 1)),
                    IARG_REG_VALUE, INS_OperandReg(ins, 0),
                    IARG_REG_VALUE, INS_OperandReg(ins, 1),
                    IARG_END);
        } else if (INS_OperandIsMemory(ins, 1)) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_cmp_memtoreg,
                    IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
                    IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
                    IARG_MEMORYREAD_EA,
                    IARG_REG_VALUE, INS_OperandReg(ins, 0),
                    IARG_END);
        } else {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_cmp_immtoreg,
                    IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
                    IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
                    IARG_UINT64, INS_OperandImmediate(ins, 1),
                    IARG_END);
        }
    } else {
        if (INS_OperandIsReg(ins, 1)) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_cmp_memtoreg,
                    IARG_UINT32, getRegSize(INS_OperandReg(ins, 1)),
                    IARG_UINT32, getTaintReg(INS_OperandReg(ins, 1)),
                    IARG_MEMORYREAD_EA,
                    IARG_REG_VALUE, INS_OperandReg(ins, 1),
                    IARG_END);
        } else {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_cmp_immtomem,
                    IARG_UINT32, INS_OperandWidth(ins, 0)/8,
                    IARG_UINT64, INS_OperandImmediate(ins, 1),
                    IARG_MEMORYREAD_EA,
                    IARG_END);
        }
    }
}

/* Arithmetic handlers */
static void handle_arith_regtoreg(unsigned N, uint32_t dest, uint32_t src) {
    for (unsigned n = 0; n < N; ++n) {
        if (g_regTags[src + n])
            g_regTags[dest + n] = g_regTags[src + n];
    }

    if (N == 4)
        for (unsigned n = 4; n < 8; ++n)
            g_regTags[dest + n] = 0;
}

static void handle_arith_memtoreg(unsigned N, uint32_t dest, char *addr) {
    tag_t *shadow = addrToShadow(addr);

    for (unsigned n = 0; n < N; ++n) {
        if (shadow[n])
            g_regTags[dest + n] = shadow[n];
    }

    if (N == 4)
        for (unsigned n = 4; n < 8; ++n)
            g_regTags[dest + n] = 0;
}

static void handle_arith_immtoreg(unsigned N, uint32_t dest) {
    if (N == 4)
        for (unsigned n = 4; n < 8; ++n)
            g_regTags[dest + n] = 0;
}

static void handle_arith_regtomem(unsigned N, char *addr, uint32_t src) {
    tag_t *shadow = addrToShadow(addr);

    for (unsigned n = 0; n < N; ++n) {
        if (g_regTags[src + n])
            shadow[n] = g_regTags[src + n];
    }
}

// static void handle_arith_immtomem(unsigned N, char *addr, uint32_t src) {
//
// }

static void handle_arith(INS ins) {
    if (INS_OperandIsReg(ins, 0)) {
        if (INS_OperandIsReg(ins, 1)) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_arith_regtoreg,
                    IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
                    IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
                    IARG_UINT32, getTaintReg(INS_OperandReg(ins, 1)),
                    IARG_END);
        } else if (INS_OperandIsMemory(ins, 1)) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_arith_memtoreg,
                    IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
                    IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
                    IARG_MEMORYREAD_EA,
                    IARG_END);
        } else {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_arith_immtoreg,
                    IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
                    IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
                    IARG_END);
        }
    } else if (INS_OperandIsMemory(ins, 0)) {
        if (INS_OperandIsReg(ins, 1)) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_arith_regtomem,
                    IARG_UINT32, getRegSize(INS_OperandReg(ins, 1)),
                    IARG_MEMORYWRITE_EA,
                    IARG_UINT32, getTaintReg(INS_OperandReg(ins, 1)),
                    IARG_END);
        }
    }
}

/* Shift operation handles */
static void handle_shl_reg(uint32_t dest) {
    g_regTags[dest + 3] = g_regTags[dest + 1];
    g_regTags[dest + 2] = g_regTags[dest + 0];

    g_regTags[dest + 1] = 0;
    g_regTags[dest + 0] = 0;

    g_regTags[dest + 4] = 0;
    g_regTags[dest + 5] = 0;
    g_regTags[dest + 6] = 0;
    g_regTags[dest + 7] = 0;
}

static void handle_shl(INS ins) {
    if (INS_OperandIsReg(ins, 1)) {
        INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)handle_shl_reg,
                IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
                IARG_END);
    }
}

static void handle_shr_reg(uint32_t dest) {
    g_regTags[dest + 0] = g_regTags[dest + 2];
    g_regTags[dest + 1] = g_regTags[dest + 3];

    g_regTags[dest + 2] = 0;
    g_regTags[dest + 3] = 0;

    g_regTags[dest + 4] = 0;
    g_regTags[dest + 5] = 0;
    g_regTags[dest + 6] = 0;
    g_regTags[dest + 7] = 0;
}

static void handle_shr(INS ins) {
    if (INS_OperandIsReg(ins, 1)) {
        INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)handle_shr_reg,
                IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
                IARG_END);
    }
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
	case XED_ICLASS_SHL:
	       handle_shl(ins);
	       break;
	case XED_ICLASS_SHR:
	       handle_shr(ins);
	       break;
	case XED_ICLASS_ADD:
	case XED_ICLASS_SUB:
	case XED_ICLASS_SBB:
	case XED_ICLASS_ROR:
	case XED_ICLASS_XOR:
	case XED_ICLASS_AND:
	case XED_ICLASS_OR:
        if (ins_opcode == XED_ICLASS_XOR &&
            INS_OperandIsReg(ins, 0) && 
            INS_OperandIsReg(ins, 1) && 
            INS_OperandReg(ins, 0) == INS_OperandReg(ins, 1)) {

            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_clear_reg,
                    IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
                    IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
                    IARG_END);
            break;
        }
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
		if (INS_OperandIsReg(ins, 0)) {
			INS_InsertCall(ins, IPOINT_BEFORE,
					(AFUNPTR)handle_clear_reg,
					IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
					IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
					IARG_END);
		} else {
			INS_InsertCall(ins, IPOINT_BEFORE,
					(AFUNPTR)handle_clear_mem,
					IARG_UINT32, INS_OperandWidth(ins, 0)/8,
					IARG_MEMORYWRITE_EA,
					IARG_END);
		}
		break;
	case XED_ICLASS_PUSH:
		/* We implemented PUSH/POP for you. */
		if (INS_OperandIsReg(ins, 0)) {
			INS_InsertCall(ins, IPOINT_BEFORE,
				(AFUNPTR)handle_mov_regtomem,
				IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
				IARG_MEMORYWRITE_EA,
				IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
				IARG_END);
		} else if (INS_OperandIsMemory(ins, 0)) {
			INS_InsertCall(ins, IPOINT_BEFORE,
				(AFUNPTR)handle_mov_memtomem,
				IARG_UINT32, INS_OperandWidth(ins, 0)/8,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_END);
		} else {
			INS_InsertCall(ins, IPOINT_BEFORE,
				(AFUNPTR)handle_clear_mem,
				IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
				IARG_MEMORYWRITE_EA,
				IARG_END);
		}
		break;
	case XED_ICLASS_POP:
		if (INS_OperandIsReg(ins, 0)) {
			INS_InsertCall(ins, IPOINT_BEFORE,
				(AFUNPTR)handle_mov_memtoreg,
				IARG_UINT32, getRegSize(INS_OperandReg(ins, 0)),
				IARG_MEMORYREAD_EA,
				IARG_UINT32, getTaintReg(INS_OperandReg(ins, 0)),
				IARG_END);
		} else {
			INS_InsertCall(ins, IPOINT_BEFORE,
				(AFUNPTR)handle_mov_memtomem,
				IARG_UINT32, INS_OperandWidth(ins, 0)/8,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_END);
		}
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
        g_ident[n] = buf[n];
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
    std::ofstream out("out.txt", std::ios::binary);
    out.write((const char*)g_ident, IDENTITY_FILE_SIZE);
    out.close();

    int count = 0;
    for (unsigned n = 0; n < IDENTITY_FILE_SIZE; ++n) {
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

