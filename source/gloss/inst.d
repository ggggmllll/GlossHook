module gloss.inst;

version(AArch64) {} else version(ARM) {} else static assert(0, "unsupport arch");

version(LDC) {} else static assert(0, "unsupport compiler");

import gloss.hook;
import ldc.llvmasm;

enum conds { EQ, NE, CS, HS = CS, CC, LO = CC, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL, NV, MAX_COND }

int CheckAbsoluteJump(uint addr);
int CheckRelativeJump(uint addr);

enum branchs { B_COND16, B_COND, B_16, B, BL, BLX, MAX_BRANCH }
branchs GetBranch(uint addr, i_set mode);

version(ARM)
{
    bool IsThumb32(uint addr);

    void MakeThumb16NOP(uint addr, size_t size);
    void MakeThumb32NOP(uint addr, size_t size);
    void MakeThumbRET(uint addr, ubyte type);

    ushort MakeThumb16B(uint addr, uint dest);
    ushort MakeThumb16BCond(uint addr, uint dest, conds cond);
    uint MakeThumb32B(uint addr, uint dest);
    uint MakeThumb32BCond(uint addr, uint dest, conds cond);
    uint MakeThumbBL(uint addr, uint func);
    uint MakeThumbBL_W(uint addr, uint func);
    uint MakeThumbBLX(uint addr, uint func);
    uint MakeThumbBLX_W(uint addr, uint func);
    ushort MakeThumbCB(uint addr, uint dest, gloss_reg.e_reg reg, bool is_cbnz);
    byte MakeThumbAbsoluteJump(uint addr, uint dest);

    uint GetThumb16BranchDestination(uint addr);
    uint GetThumb32BranchDestination(uint addr);

    void MakeArmNOP(uint addr, size_t size);
    void MakeArmRET(uint addr, ubyte type);

    uint MakeArmB(uint addr, uint dest, conds cond = conds.AL);
    uint MakeArmBL(uint addr, uint func, conds cond = conds.AL);
    uint MakeArmBLX(uint addr, uint func);
    byte MakeArmAbsoluteJump(uint addr, uint dest);

    uint GetArmBranchDestination(uint addr);
}
else
{
    void MakeArm64NOP(ulong addr, size_t size);
    void MakeArm64RET(ulong addr, ubyte type);
    uint MakeArm64B(ulong addr, ulong dest);
    uint MakeArm64BCond(ulong addr, ulong dest, conds cond);
    uint MakeArm64BL(ulong addr, ulong func);
    uint MakeArm64CB(ulong addr, ulong dest, ubyte reg, bool is_cbnz, bool is64);
    byte MakeArm64AbsoluteJump(ulong addr, ulong dest, gloss_reg.e_reg reg = gloss_reg.e_reg.X17);
    byte MakeArm64AbsoluteJump32(ulong addr, ulong dest, gloss_reg.e_reg reg = gloss_reg.e_reg.X17);
    byte MakeArm64AbsoluteJumpRet(ulong addr, ulong dest, gloss_reg.e_reg reg = gloss_reg.e_reg.X17);

    ulong GetArm64BranchDestination(ulong addr);
}

alias _inst_func = void function();

int WriteByte(uint addr, _inst_func inst_fun, size_t len);

static pragma(inline) void GLOSS_WRITE_T32(string inst)(uint addr)
{
    _inst_func func = __asm (
            ".thumb\n" ~ inst ~ "\n",
            ""
        );
    WriteByte(addr, func, uint.sizeof);
}

static pragma(inline) void GLOSS_WRITE_T16(string inst)(uint addr)
{
    _inst_func func = __asm (
            ".thumb\n" ~ inst ~ "\n",
            ""
        );
    WriteByte(addr, func, ushort.sizeof);
}

static pragma(inline) void GLOSS_WRITE_A32(string inst)(uint addr)
{
    _inst_func func = __asm (
            ".arm\n" ~ inst ~ "\n",
            ""
        );
    WriteByte(addr, func, uint.sizeof);
}

static pragma(inline) void GLOSS_WRITE_A64(string inst)(uint addr)
{
    _inst_func func = __asm (
            ".arm64\n" ~ inst ~ "\n",
            ""
        );
    WriteByte(addr, func, uint.sizeof);
}