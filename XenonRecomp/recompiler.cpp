#include <algorithm>
#include "pch.h"
#include "recompiler.h"
#include <xex_patcher.h>

static uint64_t ComputeMask(uint32_t mstart, uint32_t mstop)
{
    mstart &= 0x3F;
    mstop &= 0x3F;
    uint64_t value = (UINT64_MAX >> mstart) ^ ((mstop >= 63) ? 0 : UINT64_MAX >> (mstop + 1));
    return mstart <= mstop ? value : ~value;
}

bool Recompiler::LoadConfig(const std::string_view& configFilePath)
{
    config.Load(configFilePath);

    std::vector<uint8_t> file;
    if (!config.patchedFilePath.empty())
        file = LoadFile((config.directoryPath + config.patchedFilePath).c_str());

    if (file.empty())
    {
        file = LoadFile((config.directoryPath + config.filePath).c_str());

        if (!config.patchFilePath.empty())
        {
            const auto patchFile = LoadFile((config.directoryPath + config.patchFilePath).c_str());
            if (!patchFile.empty())
            {
                std::vector<uint8_t> outBytes;
                auto result = XexPatcher::apply(file.data(), file.size(), patchFile.data(), patchFile.size(), outBytes, false);
                if (result == XexPatcher::Result::Success)
                {
                    std::exchange(file, outBytes);

                    if (!config.patchedFilePath.empty())
                    {
                        std::ofstream stream(config.directoryPath + config.patchedFilePath, std::ios::binary);
                        if (stream.good())
                        {
                            stream.write(reinterpret_cast<const char*>(file.data()), file.size());
                            stream.close();
                        }
                    }
                }
                else
                {
                    fmt::print("ERROR: Unable to apply the patch file, ");

                    switch (result)
                    {
                    case XexPatcher::Result::XexFileUnsupported:
                        fmt::println("XEX file unsupported");
                        break;

                    case XexPatcher::Result::XexFileInvalid:
                        fmt::println("XEX file invalid");
                        break;

                    case XexPatcher::Result::PatchFileInvalid:
                        fmt::println("patch file invalid");
                        break;

                    case XexPatcher::Result::PatchIncompatible:
                        fmt::println("patch file incompatible");
                        break;

                    case XexPatcher::Result::PatchFailed:
                        fmt::println("patch failed");
                        break;

                    case XexPatcher::Result::PatchUnsupported:
                        fmt::println("patch unsupported");
                        break;

                    default:
                        fmt::println("reason unknown");
                        break;
                    }

                    return false;
                }
            }
            else
            {
                fmt::println("ERROR: Unable to load the patch file");
                return false;
            }
        }
    }

    image = Image::ParseImage(file.data(), file.size());
    return true;
}

void Recompiler::Analyse()
{
    for (size_t i = 14; i < 128; i++)
    {
        if (i < 32)
        {
            if (config.restGpr14Address != 0)
            {
                auto& restgpr = functions.emplace_back();
                restgpr.base = config.restGpr14Address + (i - 14) * 4;
                restgpr.size = (32 - i) * 4 + 12;
                image.symbols.emplace(Symbol{ fmt::format("__restgprlr_{}", i), restgpr.base, restgpr.size, Symbol_Function });
            }

            if (config.saveGpr14Address != 0)
            {
                auto& savegpr = functions.emplace_back();
                savegpr.base = config.saveGpr14Address + (i - 14) * 4;
                savegpr.size = (32 - i) * 4 + 8;
                image.symbols.emplace(fmt::format("__savegprlr_{}", i), savegpr.base, savegpr.size, Symbol_Function);
            }

            if (config.restFpr14Address != 0)
            {
                auto& restfpr = functions.emplace_back();
                restfpr.base = config.restFpr14Address + (i - 14) * 4;
                restfpr.size = (32 - i) * 4 + 4;
                image.symbols.emplace(fmt::format("__restfpr_{}", i), restfpr.base, restfpr.size, Symbol_Function);
            }

            if (config.saveFpr14Address != 0)
            {
                auto& savefpr = functions.emplace_back();
                savefpr.base = config.saveFpr14Address + (i - 14) * 4;
                savefpr.size = (32 - i) * 4 + 4;
                image.symbols.emplace(fmt::format("__savefpr_{}", i), savefpr.base, savefpr.size, Symbol_Function);
            }

            if (config.restVmx14Address != 0)
            {
                auto& restvmx = functions.emplace_back();
                restvmx.base = config.restVmx14Address + (i - 14) * 8;
                restvmx.size = (32 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__restvmx_{}", i), restvmx.base, restvmx.size, Symbol_Function);
            }

            if (config.saveVmx14Address != 0)
            {
                auto& savevmx = functions.emplace_back();
                savevmx.base = config.saveVmx14Address + (i - 14) * 8;
                savevmx.size = (32 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__savevmx_{}", i), savevmx.base, savevmx.size, Symbol_Function);
            }
        }

        if (i >= 64)
        {
            if (config.restVmx64Address != 0)
            {
                auto& restvmx = functions.emplace_back();
                restvmx.base = config.restVmx64Address + (i - 64) * 8;
                restvmx.size = (128 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__restvmx_{}", i), restvmx.base, restvmx.size, Symbol_Function);
            }

            if (config.saveVmx64Address != 0)
            {
                auto& savevmx = functions.emplace_back();
                savevmx.base = config.saveVmx64Address + (i - 64) * 8;
                savevmx.size = (128 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__savevmx_{}", i), savevmx.base, savevmx.size, Symbol_Function);
            }
        }
    }

    for (auto& [address, size] : config.functions)
    {
        functions.emplace_back(address, size);
        image.symbols.emplace(fmt::format("sub_{:X}", address), address, size, Symbol_Function);
    }

    auto& pdata = *image.Find(".pdata");
    size_t count = pdata.size / sizeof(IMAGE_CE_RUNTIME_FUNCTION);
    auto* pf = (IMAGE_CE_RUNTIME_FUNCTION*)pdata.data;
    for (size_t i = 0; i < count; i++)
    {
        auto fn = pf[i];
        fn.BeginAddress = ByteSwap(fn.BeginAddress);
        fn.Data = ByteSwap(fn.Data);

        // A .pdata table is sized to its section, not to its contents, so the
        // tail of it is zero padding. Rainbow Islands Towering Adventure has
        // 18,531 slots of which the last 1,707 are zeroes.
        //
        // Read literally, each of those is a function at address 0 of length 0,
        // and both halves of that do damage. The address puts 1,707 identical
        // `{ 0x0, sub_0 }` rows at the head of ppc_func_mapping.cpp, which the
        // runtime's function table cannot resolve. The length leaves the decode
        // loop in Recompile() with zero iterations, so the "runs off its end"
        // check that follows it reads an ppc_insn that was never written.
        //
        // Neither is specific to this title: no image has a function at address
        // zero, and no function is zero instructions long.
        if (fn.BeginAddress == 0 || fn.FunctionLength == 0)
            continue;

        if (image.symbols.find(fn.BeginAddress) == image.symbols.end())
        {
            auto& f = functions.emplace_back();
            f.base = fn.BeginAddress;
            f.size = fn.FunctionLength * 4;

            image.symbols.emplace(fmt::format("sub_{:X}", f.base), f.base, f.size, Symbol_Function);
        }
    }

    for (const auto& section : image.sections)
    {
        if (!(section.flags & SectionFlags_Code))
        {
            continue;
        }
        size_t base = section.base;
        uint8_t* data = section.data;
        uint8_t* dataEnd = section.data + section.size;

        while (data < dataEnd)
        {
            uint32_t insn = ByteSwap(*(uint32_t*)data);
            if (PPC_OP(insn) == PPC_OP_B && PPC_BL(insn))
            {
                size_t address = base + (data - section.data) + PPC_BI(insn);

                if (address >= section.base && address < section.base + section.size && image.symbols.find(address) == image.symbols.end())
                {
                    auto data = section.data + address - section.base;
                    auto& fn = functions.emplace_back(Function::Analyze(data, section.base + section.size - address, address));
                    image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);
                }
            }
            data += 4;
        }

        data = section.data;

        while (data < dataEnd)
        {
            auto invalidInstr = config.invalidInstructions.find(ByteSwap(*(uint32_t*)data));
            if (invalidInstr != config.invalidInstructions.end())
            {
                base += invalidInstr->second;
                data += invalidInstr->second;
                continue;
            }

            auto fnSymbol = image.symbols.find(base);
            if (fnSymbol != image.symbols.end() && fnSymbol->address == base && fnSymbol->type == Symbol_Function)
            {
                assert(fnSymbol->address == base);

                base += fnSymbol->size;
                data += fnSymbol->size;
            }
            else
            {
                auto& fn = functions.emplace_back(Function::Analyze(data, dataEnd - data, base));
                image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);

                base += fn.size;
                data += fn.size;
            }
        }
    }

    std::sort(functions.begin(), functions.end(), [](auto& lhs, auto& rhs)
        {
            if (lhs.base != rhs.base)
                return lhs.base < rhs.base;
            // Largest first, so the de-duplication below keeps it.
            return lhs.size > rhs.size;
        });

    // Functions are discovered by four independent passes - the config, the
    // .pdata table, a scan for `bl` targets and a linear walk - and nothing
    // stops two of them landing on the same address. When that happens the
    // same function is emitted twice and the output does not link. Keeping the
    // largest span is the right choice: a longer analysis is the one that saw
    // more of the function before it stopped.
    functions.erase(std::unique(functions.begin(), functions.end(),
        [](const auto& lhs, const auto& rhs) { return lhs.base == rhs.base; }),
        functions.end());
}

bool Recompiler::Recompile(
    const Function& fn,
    uint32_t base,
    const ppc_insn& insn,
    const uint32_t* data,
    std::unordered_map<uint32_t, RecompilerSwitchTable>::iterator& switchTable,
    RecompilerLocalVariables& localVariables,
    CSRState& csrState)
{
    println("\t// {} {}", insn.opcode->name, insn.op_str);

    // TODO: we could cache these formats in an array
    auto r = [&](size_t index)
        {
            if ((config.nonArgumentRegistersAsLocalVariables && (index == 0 || index == 2 || index == 11 || index == 12)) || 
                (config.nonVolatileRegistersAsLocalVariables && index >= 14))
            {
                localVariables.r[index] = true;
                return fmt::format("r{}", index);
            }
            return fmt::format("ctx.r{}", index);
        };

    auto f = [&](size_t index)
        {
            if ((config.nonArgumentRegistersAsLocalVariables && index == 0) ||
                (config.nonVolatileRegistersAsLocalVariables && index >= 14))
            {
                localVariables.f[index] = true;
                return fmt::format("f{}", index);
            }
            return fmt::format("ctx.f{}", index);
        };

    auto v = [&](size_t index)
        {
            if ((config.nonArgumentRegistersAsLocalVariables && (index >= 32 && index <= 63)) ||
                (config.nonVolatileRegistersAsLocalVariables && ((index >= 14 && index <= 31) || (index >= 64 && index <= 127))))
            {
                localVariables.v[index] = true;
                return fmt::format("v{}", index);
            }
            return fmt::format("ctx.v{}", index);
        };

    auto cr = [&](size_t index)
        {
            if (config.crRegistersAsLocalVariables)
            {
                localVariables.cr[index] = true;
                return fmt::format("cr{}", index);
            }
            return fmt::format("ctx.cr{}", index);
        };

    auto ctr = [&]()
        {
            if (config.ctrAsLocalVariable)
            {
                localVariables.ctr = true;
                return "ctr";
            }
            return "ctx.ctr";
        };

    auto xer = [&]()
        {
            if (config.xerAsLocalVariable)
            {
                localVariables.xer = true;
                return "xer";
            }
            return "ctx.xer";
        };

    auto reserved = [&]()
        {
            if (config.reservedRegisterAsLocalVariable)
            {
                localVariables.reserved = true;
                return "reserved";
            }
            return "ctx.reserved";
        };

    auto temp = [&]()
        {
            localVariables.temp = true;
            return "temp";
        };

    auto vTemp = [&]()
        {
            localVariables.vTemp = true;
            return "vTemp";
        };

    auto env = [&]()
        {
            localVariables.env = true;
            return "env";
        };

    auto ea = [&]()
        {
            localVariables.ea = true;
            return "ea";
        };

    // TODO (Sajid): Check for out of bounds access
    auto mmioStore = [&]() -> bool
        {
            return *(data + 1) == c_eieio;
        };

    auto printFunctionCall = [&](uint32_t address)
        {
            if (address == config.longJmpAddress)
            {
                println("\tlongjmp(*reinterpret_cast<jmp_buf*>(base + {}.u32), {}.s32);", r(3), r(4));
            }
            else if (address == config.setJmpAddress)
            {
                println("\t{} = ctx;", env());
                println("\t{}.s64 = setjmp(*reinterpret_cast<jmp_buf*>(base + {}.u32));", temp(), r(3));
                println("\tif ({}.s64 != 0) ctx = {};", temp(), env());
                println("\t{} = {};", r(3), temp());
            }
            else
            {
                auto targetSymbol = image.symbols.find(address);

                if (targetSymbol != image.symbols.end() && targetSymbol->address == address && targetSymbol->type == Symbol_Function)
                {
                    if (config.nonVolatileRegistersAsLocalVariables && (targetSymbol->name.find("__rest") == 0 || targetSymbol->name.find("__save") == 0))
                    {
                        // print nothing
                    }
                    else
                    {
                        println("\t{}(ctx, base);", targetSymbol->name);
                    }
                }
                else
                {
                    println("\t// ERROR {:X}", address);
                }
            }
        };

    auto printConditionalBranch = [&](bool not_, const std::string_view& cond)
        {
            if (insn.operands[1] < fn.base || insn.operands[1] >= fn.base + fn.size)
            {
                println("\tif ({}{}.{}) {{", not_ ? "!" : "", cr(insn.operands[0]), cond);
                print("\t");
                printFunctionCall(insn.operands[1]);
                println("\t\treturn;");
                println("\t}}");
            }
            else
            {
                println("\tif ({}{}.{}) goto loc_{:X};", not_ ? "!" : "", cr(insn.operands[0]), cond, insn.operands[1]);
            }
        };

    // The CTR-decrement branch family (bdz/bdnz and their condition-tested
    // forms) can target another function exactly like the plain conditional
    // branches above - compilers fold shared loop tails that way, so the target
    // lands past this function's end. Those cases used to emit a bare
    // `goto loc_X` for such a target, naming a label that is never emitted, and
    // the translation unit then failed to compile with "use of undeclared
    // label". Mirror printConditionalBranch: tail-call when the target is
    // outside this function, goto when it is inside.
    auto printCtrBranch = [&](const std::string& cond, uint32_t target)
        {
            if (target < fn.base || target >= fn.base + fn.size)
            {
                println("\tif ({}) {{", cond);
                print("\t");
                printFunctionCall(target);
                println("\t\treturn;");
                println("\t}}");
            }
            else
            {
                println("\tif ({}) goto loc_{:X};", cond, target);
            }
        };

    auto printSetFlushMode = [&](bool enable)
        {
            auto newState = enable ? CSRState::VMX : CSRState::FPU;
            if (csrState != newState)
            {
                auto prefix = enable ? "enable" : "disable";
                auto suffix = csrState != CSRState::Unknown ? "Unconditional" : "";
                println("\tctx.fpscr.{}FlushMode{}();", prefix, suffix);

                csrState = newState;
            }
        };

    auto midAsmHook = config.midAsmHooks.find(base);

    auto printMidAsmHook = [&]()
        {
            bool returnsBool = midAsmHook->second.returnOnFalse || midAsmHook->second.returnOnTrue ||
                midAsmHook->second.jumpAddressOnFalse != NULL || midAsmHook->second.jumpAddressOnTrue != NULL;

            print("\t");
            if (returnsBool)
                print("if (");

            print("{}(", midAsmHook->second.name);
            for (auto& reg : midAsmHook->second.registers)
            {
                if (out.back() != '(')
                    out += ", ";

                switch (reg[0])
                {
                case 'c':
                    if (reg == "ctr")
                        out += ctr();
                    else
                        out += cr(std::atoi(reg.c_str() + 2));
                    break;

                case 'x':
                    out += xer();
                    break;

                case 'r':
                    if (reg == "reserved")
                        out += reserved();
                    else
                        out += r(std::atoi(reg.c_str() + 1));
                    break;

                case 'f':
                    if (reg == "fpscr")
                        out += "ctx.fpscr";
                    else
                        out += f(std::atoi(reg.c_str() + 1));
                    break;

                case 'v':
                    out += v(std::atoi(reg.c_str() + 1));
                    break;
                }
            }

            if (returnsBool)
            {
                println(")) {{");

                if (midAsmHook->second.returnOnTrue)
                    println("\t\treturn;");
                else if (midAsmHook->second.jumpAddressOnTrue != NULL)
                    println("\t\tgoto loc_{:X};", midAsmHook->second.jumpAddressOnTrue);

                println("\t}}");

                println("\telse {{");

                if (midAsmHook->second.returnOnFalse)
                    println("\t\treturn;");
                else if (midAsmHook->second.jumpAddressOnFalse != NULL)
                    println("\t\tgoto loc_{:X};", midAsmHook->second.jumpAddressOnFalse);

                println("\t}}");
            }
            else
            {
                println(");");

                if (midAsmHook->second.ret)
                    println("\treturn;");
                else if (midAsmHook->second.jumpAddress != NULL)
                    println("\tgoto loc_{:X};", midAsmHook->second.jumpAddress);
            }
        };

    if (midAsmHook != config.midAsmHooks.end() && !midAsmHook->second.afterInstruction)
        printMidAsmHook();

    int id = insn.opcode->id;

    // Handling instructions that don't disassemble correctly for some reason here
    if (id == PPC_INST_VUPKHSB128 && insn.operands[2] == 0x60) id = PPC_INST_VUPKHSH128;
    else if (id == PPC_INST_VUPKLSB128 && insn.operands[2] == 0x60) id = PPC_INST_VUPKLSH128;

    switch (id)
    {
    case PPC_INST_ADD:
        println("\t{}.u64 = {}.u64 + {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDC:
        println("\t{}.ca = {}.u32 > ~{}.u32;", xer(), r(insn.operands[2]), r(insn.operands[1]));
        println("\t{}.u64 = {}.u64 + {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDE:
        println("\t{}.u8 = ({}.u32 + {}.u32 < {}.u32) | ({}.u32 + {}.u32 + {}.ca < {}.ca);", temp(), r(insn.operands[1]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[1]), r(insn.operands[2]), xer(), xer());
        println("\t{}.u64 = {}.u64 + {}.u64 + {}.ca;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        println("\t{}.ca = {}.u8;", xer(), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDME:
        println("\t{}.u8 = ({}.u32 - 1 < {}.u32) | ({}.u32 - 1 + {}.ca < {}.ca);", temp(), r(insn.operands[1]), r(insn.operands[1]), r(insn.operands[1]), xer(), xer());
        println("\t{}.u64 = {}.u64 - 1 + {}.ca;", r(insn.operands[0]), r(insn.operands[1]), xer());
        println("\t{}.ca = {}.u8;", xer(), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDI:
        print("\t{}.s64 = ", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.s64 + ", r(insn.operands[1]));
        println("{};", int32_t(insn.operands[2]));
        break;

    case PPC_INST_ADDIC:
        println("\t{}.ca = {}.u32 > {};", xer(), r(insn.operands[1]), ~insn.operands[2]);
        println("\t{}.s64 = {}.s64 + {};", r(insn.operands[0]), r(insn.operands[1]), int32_t(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDIS:
        print("\t{}.s64 = ", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.s64 + ", r(insn.operands[1]));
        println("{};", static_cast<int32_t>(insn.operands[2] << 16));
        break;

    case PPC_INST_ADDZE:
        println("\t{}.s64 = {}.s64 + {}.ca;", temp(), r(insn.operands[1]), xer());
        println("\t{}.ca = {}.u32 < {}.u32;", xer(), temp(), r(insn.operands[1]));
        println("\t{}.s64 = {}.s64;", r(insn.operands[0]), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_AND:
        println("\t{}.u64 = {}.u64 & {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ANDC:
        println("\t{}.u64 = {}.u64 & ~{}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ANDI:
        println("\t{}.u64 = {}.u64 & {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ANDIS:
        println("\t{}.u64 = {}.u64 & {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2] << 16);
        println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ATTN:
        // undefined instruction
        break;

    case PPC_INST_B:
        if (insn.operands[0] < fn.base || insn.operands[0] >= fn.base + fn.size)
        {
            printFunctionCall(insn.operands[0]);
            println("\treturn;");
        }
        else
        {
            println("\tgoto loc_{:X};", insn.operands[0]);
        }
        break;

    case PPC_INST_BCTR:
        if (switchTable != config.switchTables.end())
        {
            // The index is the LOW 32 BITS of the register, not the whole 64.
            // A PPC switch scales its index with `rlwinm rT,rIDX,2,0,29`, which
            // reads the low word and zero-extends - so the hardware indexes the
            // table with the low 32 bits however dirty the high half is. And the
            // high half is often dirty: `addi rIDX,rIDX,N` on a value like
            // 0xFFFFFFEE carries into bit 32, leaving 0x1_00000001. The bounds
            // check ahead of the dispatch is a `cmplwi`, so it compares the low
            // word and passes. Switching on .u64 then matches no case at all,
            // and the default is `__builtin_unreachable()` - a wild jump.
            // Space Giraffe crashed on exactly this at 0x82151348 with the
            // index register holding 0x100000001.
            println("\tswitch ({}.u32) {{", r(switchTable->second.r));

            for (size_t i = 0; i < switchTable->second.labels.size(); i++)
            {
                println("\tcase {}:", i);
                auto label = switchTable->second.labels[i];
                if (label < fn.base || label >= fn.base + fn.size)
                {
                    // Some compiler-generated dispatchers share case bodies
                    // with a neighboring entry point. A branch to an external
                    // recompiled function followed by return has the same tail
                    // semantics as the guest bctr, and also supports a case
                    // body located before this function's nominal start.
                    print("\t");
                    printFunctionCall(label);
                    println("\t\treturn;");
                }
                else
                {
                    println("\t\tgoto loc_{:X};", label);
                }
            }

            println("\tdefault:");
            println("\t\t__builtin_unreachable();");
            println("\t}}");

            switchTable = config.switchTables.end();
        }
        else
        {
            println("\tPPC_CALL_INDIRECT_FUNC({}.u32);", ctr());
            println("\treturn;");
        }
        break;

    case PPC_INST_BCTRL:
        if (!config.skipLr)
            println("\tctx.lr = 0x{:X};", base + 4);
        println("\tPPC_CALL_INDIRECT_FUNC({}.u32);", ctr());
        csrState = CSRState::Unknown; // the call could change it
        break;

    case PPC_INST_BDZ:
        println("\t--{}.u64;", ctr());
        printCtrBranch(fmt::format("{}.u32 == 0", ctr()), insn.operands[0]);
        break;

    case PPC_INST_BDZF:
    {
        constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
        println("\t--{}.u64;", ctr());
        printCtrBranch(fmt::format("{}.u32 == 0 && !{}.{}", ctr(), cr(insn.operands[0] / 4), fields[insn.operands[0] % 4]), insn.operands[1]);
        break;
    }

    case PPC_INST_BDZLR:
        println("\t--{}.u64;", ctr());
        println("\tif ({}.u32 == 0) return;", ctr(), insn.operands[0]);
        break;

    case PPC_INST_BDNZ:
        println("\t--{}.u64;", ctr());
        printCtrBranch(fmt::format("{}.u32 != 0", ctr()), insn.operands[0]);
        break;

    case PPC_INST_BDNZF:
    {
        constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
        println("\t--{}.u64;", ctr());
        printCtrBranch(fmt::format("{}.u32 != 0 && !{}.{}", ctr(), cr(insn.operands[0] / 4), fields[insn.operands[0] % 4]), insn.operands[1]);
        break;
    }

    case PPC_INST_BDNZT:
    {
        constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
        println("\t--{}.u64;", ctr());
        printCtrBranch(fmt::format("{}.u32 != 0 && {}.{}", ctr(), cr(insn.operands[0] / 4), fields[insn.operands[0] % 4]), insn.operands[1]);
        break;
    }

    case PPC_INST_BEQ:
        printConditionalBranch(false, "eq");
        break;

    case PPC_INST_BEQLR:
        println("\tif ({}.eq) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BGE:
        printConditionalBranch(true, "lt");
        break;

    case PPC_INST_BGELR:
        println("\tif (!{}.lt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BGT:
        printConditionalBranch(false, "gt");
        break;

    case PPC_INST_BGTLR:
        println("\tif ({}.gt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BL:
        if (!config.skipLr)
            println("\tctx.lr = 0x{:X};", base + 4);
        printFunctionCall(insn.operands[0]);
        csrState = CSRState::Unknown; // the call could change it
        break;

    case PPC_INST_BLE:
        printConditionalBranch(true, "gt");
        break;

    case PPC_INST_BLELR:
        println("\tif (!{}.gt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BLR:
        println("\treturn;");
        break;

    case PPC_INST_BLRL:
        println("__builtin_debugtrap();");
        break;

    case PPC_INST_BLT:
        printConditionalBranch(false, "lt");
        break;

    case PPC_INST_BLTLR:
        println("\tif ({}.lt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BNE:
        printConditionalBranch(true, "eq");
        break;

    case PPC_INST_BSO:
        printConditionalBranch(false, "so");
        break;

    case PPC_INST_BNS:
        printConditionalBranch(true, "so");
        break;

    case PPC_INST_BNSLR:
        println("\tif (!{}.so) return;", cr(insn.operands[0]));
        break;

    // The mirror of BNSLR, and it was missing - so `bsolr` was reported as an
    // unrecognized instruction and emitted as a bare comment, i.e. dropped.
    // After a floating-point compare the field is the UNORDERED bit (PPCCRRegister
    // unions `so` with `un`, and compare(double,double) writes `un`), so the pair
    // `bltlr crN` / `bsolr crN` is the ordinary "return unless a >= b, NaN
    // included" the MSVC PPC compiler emits. Ridge Racer 6 has 11 of them.
    case PPC_INST_BSOLR:
        println("\tif ({}.so) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BNECTR:
        println("\tif (!{}.eq) {{", cr(insn.operands[0]));
        println("\t\tPPC_CALL_INDIRECT_FUNC({}.u32);", ctr());
        println("\t\treturn;");
        println("\t}}");
        break;

    case PPC_INST_BNELR:
        println("\tif (!{}.eq) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_CCTPL:
        // no op
        break;

    case PPC_INST_CCTPM:
        // no op
        break;

    case PPC_INST_CLRLDI:
        println("\t{}.u64 = {}.u64 & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), (1ull << (64 - insn.operands[2])) - 1);
        break;

    case PPC_INST_CLRLWI:
        println("\t{}.u64 = {}.u32 & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), (1ull << (32 - insn.operands[2])) - 1);
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_CMPD:
        println("\t{}.compare<int64_t>({}.s64, {}.s64, {});", cr(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPDI:
        println("\t{}.compare<int64_t>({}.s64, {}, {});", cr(insn.operands[0]), r(insn.operands[1]), int32_t(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPLD:
        println("\t{}.compare<uint64_t>({}.u64, {}.u64, {});", cr(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPLDI:
        println("\t{}.compare<uint64_t>({}.u64, {}, {});", cr(insn.operands[0]), r(insn.operands[1]), insn.operands[2], xer());
        break;

    case PPC_INST_CMPLW:
        println("\t{}.compare<uint32_t>({}.u32, {}.u32, {});", cr(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPLWI:
        println("\t{}.compare<uint32_t>({}.u32, {}, {});", cr(insn.operands[0]), r(insn.operands[1]), insn.operands[2], xer());
        break;

    case PPC_INST_CMPW:
        println("\t{}.compare<int32_t>({}.s32, {}.s32, {});", cr(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPWI:
        println("\t{}.compare<int32_t>({}.s32, {}, {});", cr(insn.operands[0]), r(insn.operands[1]), int32_t(insn.operands[2]), xer());
        break;

    case PPC_INST_CNTLZD:
        println("\t{0}.u64 = {1}.u64 == 0 ? 64 : __builtin_clzll({1}.u64);", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_CNTLZW:
        println("\t{0}.u64 = {1}.u32 == 0 ? 32 : __builtin_clz({1}.u32);", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_CROR:
    {
        constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
        println("\t{}.{} = {}.{} | {}.{};", cr(insn.operands[0] / 4), fields[insn.operands[0] % 4], cr(insn.operands[1] / 4), fields[insn.operands[1] % 4], cr(insn.operands[2] / 4), fields[insn.operands[2] % 4]);
        break;
    }

    case PPC_INST_CRORC:
    {
        constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
        println("\t{}.{} = {}.{} | (~{}.{} & 1);", cr(insn.operands[0] / 4), fields[insn.operands[0] % 4], cr(insn.operands[1] / 4), fields[insn.operands[1] % 4], cr(insn.operands[2] / 4), fields[insn.operands[2] % 4]);
        break;
    }

    case PPC_INST_DB16CYC:
        // no op
        break;

    case PPC_INST_DCBF:
        // no op
        break;

    case PPC_INST_DCBT:
        // no op
        break;

    case PPC_INST_DCBST:
        // no op
        break;

    case PPC_INST_DCBTST:
        // no op
        break;

    case PPC_INST_DCBZ:
        // Xenon's PPE has 128-byte cache lines. Guest memset implementations
        // advance by 128 bytes per dcbz, so generic PPC's 32-byte model leaves
        // three quarters of each line untouched (and breaks SCIV startup).
        print("\tmemset(base + ((");
        if (insn.operands[0] != 0)
            print("{}.u32 + ", r(insn.operands[0]));
        println("{}.u32) & ~127), 0, 128);", r(insn.operands[1]));
        break;

    case PPC_INST_DCBZL:
        print("\tmemset(base + ((");
        if (insn.operands[0] != 0)
            print("{}.u32 + ", r(insn.operands[0]));
        println("{}.u32) & ~127), 0, 128);", r(insn.operands[1]));
        break;

    case PPC_INST_DIVD:
        println("\t{}.s64 = {}.s64 / {}.s64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_DIVDU:
        println("\t{}.u64 = {}.u64 / {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_DIVW:
        println("\t{}.s32 = {}.s32 / {}.s32;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_DIVWU:
        println("\t{}.u32 = {}.u32 / {}.u32;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_EIEIO:
        // no op
        break;

    case PPC_INST_EQV:
        println("\t{}.u64 = ~({}.u64 ^ {}.u64);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_EXTSB:
        println("\t{}.s64 = {}.s8;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_EXTSH:
        println("\t{}.s64 = {}.s16;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_EXTSW:
        println("\t{}.s64 = {}.s32;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_FABS:
        printSetFlushMode(false);
        println("\t{}.u64 = {}.u64 & ~0x8000000000000000;", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FADD:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 + {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FADDS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 + {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FCFID:
        printSetFlushMode(false);
        println("\t{}.f64 = double({}.s64);", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FCMPU:
        printSetFlushMode(false);
        println("\t{}.compare({}.f64, {}.f64);", cr(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FCTID:
        printSetFlushMode(false);
        println("\t{}.s64 = ({}.f64 > double(LLONG_MAX)) ? LLONG_MAX : _mm_cvtsd_si64(_mm_load_sd(&{}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[1]));
        break;

    case PPC_INST_FCTIDZ:
        printSetFlushMode(false);
        println("\t{}.s64 = ({}.f64 > double(LLONG_MAX)) ? LLONG_MAX : _mm_cvttsd_si64(_mm_load_sd(&{}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[1]));
        break;

    // Convert to integer word using the CURRENT rounding mode, where FCTIWZ
    // truncates - the only difference is cvtsd against cvttsd, and it is the
    // whole difference between rounding 0.5 up and dropping it. Hydro Thunder
    // Hurricane has two, at 0x827920A4 and 0x827920BC. NaN needs no special
    // case: x86 returns the integer-indefinite value 0x80000000 for it, which is
    // exactly what the PowerPC produces. The `> INT_MAX` guard is the one that
    // matters, because there the PowerPC saturates and x86 does not.
    case PPC_INST_FCTIW:
        printSetFlushMode(false);
        println("\t{}.s64 = ({}.f64 > double(INT_MAX)) ? INT_MAX : _mm_cvtsd_si32(_mm_load_sd(&{}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[1]));
        break;

    case PPC_INST_FCTIWZ:
        printSetFlushMode(false);
        println("\t{}.s64 = ({}.f64 > double(INT_MAX)) ? INT_MAX : _mm_cvttsd_si32(_mm_load_sd(&{}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[1]));
        break;

    case PPC_INST_FDIV:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 / {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FDIVS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 / {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FMADD:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 * {}.f64 + {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FMADDS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 * {}.f64 + {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FMR:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64;", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FMSUB:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 * {}.f64 - {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FMSUBS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 * {}.f64 - {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FMUL:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 * {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FMULS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 * {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FNABS:
        printSetFlushMode(false);
        println("\t{}.u64 = {}.u64 | 0x8000000000000000;", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FNEG:
        printSetFlushMode(false);
        println("\t{}.u64 = {}.u64 ^ 0x8000000000000000;", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FNMADDS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float(-({}.f64 * {}.f64 + {}.f64)));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FNMSUB:
        printSetFlushMode(false);
        println("\t{}.f64 = -({}.f64 * {}.f64 - {}.f64);", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FNMSUBS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float(-({}.f64 * {}.f64 - {}.f64)));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FRES:
        printSetFlushMode(false);
        println("\t{}.f64 = float(1.0 / {}.f64);", f(insn.operands[0]), f(insn.operands[1]));
        break;

    // Reciprocal square root estimate. The architecture only promises a few
    // bits of accuracy and callers refine it, so computing it exactly is both
    // simpler and strictly closer to the ideal than the hardware estimate.
    // Without this case the instruction is dropped as a comment: Geometry Wars
    // 2 has 104 of them, all in vector-normalise paths.
    case PPC_INST_FRSQRTE:
        printSetFlushMode(false);
        println("\t{}.f64 = 1.0 / sqrt({}.f64);", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FRSQRTES:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float(1.0 / sqrt({}.f64)));", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FRSP:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64));", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FSEL:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 >= 0.0 ? {}.f64 : {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FSQRT:
        printSetFlushMode(false);
        println("\t{}.f64 = sqrt({}.f64);", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FSQRTS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float(sqrt({}.f64)));", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FSUB:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 - {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FSUBS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 - {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_LBZ:
        print("\t{}.u64 = PPC_LOAD_U8(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LBZU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u64 = PPC_LOAD_U8({});", r(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_LBZX:
        print("\t{}.u64 = PPC_LOAD_U8(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_LBZUX:
        println("\t{} = {}.u32 + {}.u32;", ea(), r(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u64 = PPC_LOAD_U8({});", r(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[1]), ea());
        break;

    case PPC_INST_LD:
        print("\t{}.u64 = PPC_LOAD_U64(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LDARX:
        print("\t{}.u64 = *(uint64_t*)(base + ", reserved());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        println("\t{}.u64 = __builtin_bswap64({}.u64);", r(insn.operands[0]), reserved());
        break;

    case PPC_INST_LDU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u64 = PPC_LOAD_U64({});", r(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_LDX:
        print("\t{}.u64 = PPC_LOAD_U64(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_LDUX:
        println("\t{} = {}.u32 + {}.u32;", ea(), r(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u64 = PPC_LOAD_U64({});", r(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[1]), ea());
        break;

    case PPC_INST_LFD:
        printSetFlushMode(false);
        print("\t{}.u64 = PPC_LOAD_U64(", f(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LFDU:
        printSetFlushMode(false);
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        // operand 0 names an FPR, so it must go through f() - r() writes the
        // GENERAL-purpose register of the same number, which both loses the
        // loaded double and destroys whatever that GPR held. LFD and LFDX above
        // get this right; these update forms did not.
        println("\t{}.u64 = PPC_LOAD_U64({});", f(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_LFDX:
        printSetFlushMode(false);
        print("\t{}.u64 = PPC_LOAD_U64(", f(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_LFDUX:
        printSetFlushMode(false);
        println("\t{} = {}.u32 + {}.u32;", ea(), r(insn.operands[1]), r(insn.operands[2]));
        // As LFDU: operand 0 is an FPR. See the note there.
        println("\t{}.u64 = PPC_LOAD_U64({});", f(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[1]), ea());
        break;

    case PPC_INST_LFS:
        printSetFlushMode(false);
        print("\t{}.u32 = PPC_LOAD_U32(", temp());
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        println("\t{}.f64 = double({}.f32);", f(insn.operands[0]), temp());
        break;

    case PPC_INST_LFSU:
        printSetFlushMode(false);
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u32 = PPC_LOAD_U32({});", temp(), ea());
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        println("\t{}.f64 = double({}.f32);", f(insn.operands[0]), temp());
        break;

    case PPC_INST_LFSX:
        printSetFlushMode(false);
        print("\t{}.u32 = PPC_LOAD_U32(", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        println("\t{}.f64 = double({}.f32);", f(insn.operands[0]), temp());
        break;

    case PPC_INST_LFSUX:
        printSetFlushMode(false);
        println("\t{} = {}.u32 + {}.u32;", ea(), r(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u32 = PPC_LOAD_U32({});", temp(), ea());
        println("\t{}.u32 = {};", r(insn.operands[1]), ea());
        println("\t{}.f64 = double({}.f32);", f(insn.operands[0]), temp());
        break;

    case PPC_INST_LHA:
        print("\t{}.s64 = int16_t(PPC_LOAD_U16(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}));", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LHAU:
        print("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        print("\t{}.s64 = int16_t(PPC_LOAD_U16({}));", r(insn.operands[0]), ea());
        print("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_LHAX:
        print("\t{}.s64 = int16_t(PPC_LOAD_U16(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32));", r(insn.operands[2]));
        break;

    // Byte-reversed halfword load - the little-endian counterpart of lhzx,
    // which a big-endian title uses to read little-endian data (here, one call
    // site in Geometry Wars 2). Same operand form as lwbrx.
    case PPC_INST_LHBRX:
        print("\t{}.u64 = __builtin_bswap16(PPC_LOAD_U16(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32));", r(insn.operands[2]));
        break;

    case PPC_INST_LHZ:
        print("\t{}.u64 = PPC_LOAD_U16(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LHZU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u64 = PPC_LOAD_U16({});", r(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_LHZX:
        print("\t{}.u64 = PPC_LOAD_U16(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_LHZUX:
        println("\t{} = {}.u32 + {}.u32;", ea(), r(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u64 = PPC_LOAD_U16({});", r(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[1]), ea());
        break;

    case PPC_INST_LI:
        println("\t{}.s64 = {};", r(insn.operands[0]), int32_t(insn.operands[1]));
        break;

    case PPC_INST_LIS:
        println("\t{}.s64 = {};", r(insn.operands[0]), int32_t(insn.operands[1] << 16));
        break;

    case PPC_INST_LVEWX:
    case PPC_INST_LVEWX128:
    case PPC_INST_LVX:
    case PPC_INST_LVX128:
    case PPC_INST_LVEHX:
        // NOTE: for endian swapping, we reverse the whole vector instead of individual elements.
        // this is accounted for in every instruction (eg. dp3 sums yzw instead of xyz)
        print("\t_mm_store_si128((__m128i*){}.u8, _mm_shuffle_epi8(_mm_load_si128((__m128i*)(base + ((", v(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32) & ~0xF))), _mm_load_si128((__m128i*)VectorMaskL)));", r(insn.operands[2]));
        break;

    case PPC_INST_LVLX:
    case PPC_INST_LVLX128:
        print("\t{}.u32 = ", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_shuffle_epi8(_mm_load_si128((__m128i*)(base + ({}.u32 & ~0xF))), _mm_load_si128((__m128i*)&VectorMaskL[({}.u32 & 0xF) * 16])));", v(insn.operands[0]), temp(), temp());
        break;

    case PPC_INST_LVRX:
    case PPC_INST_LVRX128:
        print("\t{}.u32 = ", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));
        println("\t_mm_store_si128((__m128i*){}.u8, {}.u32 & 0xF ? _mm_shuffle_epi8(_mm_load_si128((__m128i*)(base + ({}.u32 & ~0xF))), _mm_load_si128((__m128i*)&VectorMaskR[({}.u32 & 0xF) * 16])) : _mm_setzero_si128());", v(insn.operands[0]), temp(), temp(), temp());
        break;

    case PPC_INST_LVSL:
        print("\t{}.u32 = ", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_load_si128((__m128i*)&VectorShiftTableL[({}.u32 & 0xF) * 16]));", v(insn.operands[0]), temp());
        break;

    case PPC_INST_LVSR:
        print("\t{}.u32 = ", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_load_si128((__m128i*)&VectorShiftTableR[({}.u32 & 0xF) * 16]));", v(insn.operands[0]), temp());
        break;

    case PPC_INST_LWA:
        print("\t{}.s64 = int32_t(PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}));", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LWARX:
        print("\t{}.u32 = *(uint32_t*)(base + ", reserved());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        println("\t{}.u64 = __builtin_bswap32({}.u32);", r(insn.operands[0]), reserved());
        break;

    case PPC_INST_LWAX:
        print("\t{}.s64 = int32_t(PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32));", r(insn.operands[2]));
        break;

    case PPC_INST_LWBRX:
        print("\t{}.u64 = __builtin_bswap32(PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32));", r(insn.operands[2]));
        break;

    case PPC_INST_LWSYNC:
        // no op
        break;

    case PPC_INST_LWZ:
        print("\t{}.u64 = PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LWZU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u64 = PPC_LOAD_U32({});", r(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_LWZX:
        print("\t{}.u64 = PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_LWZUX:
        println("\t{} = {}.u32 + {}.u32;", ea(), r(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u64 = PPC_LOAD_U32({});", r(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[1]), ea());
        break;

    case PPC_INST_MFCR:
        for (size_t i = 0; i < 32; i++)
        {
            constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
            println("\t{}.u64 {}= {}.{} ? 0x{:X} : 0;", r(insn.operands[0]), i == 0 ? "" : "|", cr(i / 4), fields[i % 4], 1u << (31 - i));
        }
        break;

    case PPC_INST_MFFS:
        println("\t{}.u64 = ctx.fpscr.loadFromHost();", r(insn.operands[0]));
        break;

    case PPC_INST_MFLR:
        if (!config.skipLr)
            println("\t{}.u64 = ctx.lr;", r(insn.operands[0]));
        break;

    case PPC_INST_MFMSR:
        if (!config.skipMsr)
            println("\t{}.u64 = ctx.msr;", r(insn.operands[0]));
        break;

    case PPC_INST_MFOCRF:
        // TODO: don't hardcode to cr6
        println("\t{}.u64 = ({}.lt << 7) | ({}.gt << 6) | ({}.eq << 5) | ({}.so << 4);", r(insn.operands[0]), cr(6), cr(6), cr(6), cr(6));
        break;

    case PPC_INST_MFTB:
        println("\t{}.u64 = __rdtsc();", r(insn.operands[0]));
        break;

    case PPC_INST_MR:
        println("\t{}.u64 = {}.u64;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_MTCR:
        for (size_t i = 0; i < 32; i++)
        {
            constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
            println("\t{}.{} = ({}.u32 & 0x{:X}) != 0;", cr(i / 4), fields[i % 4], r(insn.operands[0]), 1u << (31 - i));
        }
        break;

    case PPC_INST_MTCTR:
        println("\t{}.u64 = {}.u64;", ctr(), r(insn.operands[0]));
        break;

    case PPC_INST_MTFSF:
        println("\tctx.fpscr.storeFromGuest({}.u32);", f(insn.operands[1]));
        break;

    case PPC_INST_MTLR:
        if (!config.skipLr)
            println("\tctx.lr = {}.u64;", r(insn.operands[0]));
        break;

    case PPC_INST_MTMSRD:
        if (!config.skipMsr)
            println("\tctx.msr = ({}.u32 & 0x8020) | (ctx.msr & ~0x8020);", r(insn.operands[0]));
        break;

    case PPC_INST_MTXER:
        println("\t{}.so = ({}.u64 & 0x80000000) != 0;", xer(), r(insn.operands[0]));
        println("\t{}.ov = ({}.u64 & 0x40000000) != 0;", xer(), r(insn.operands[0]));
        println("\t{}.ca = ({}.u64 & 0x20000000) != 0;", xer(), r(insn.operands[0]));
        break;

    case PPC_INST_MULHW:
        println("\t{}.s64 = (int64_t({}.s32) * int64_t({}.s32)) >> 32;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_MULHWU:
        println("\t{}.u64 = (uint64_t({}.u32) * uint64_t({}.u32)) >> 32;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    // The signed form of the same trick, for a signed divisor. The sign
    // matters: a signed reciprocal multiply keeps the arithmetic high half,
    // and computing the unsigned one instead is wrong for every negative
    // input. Alien Breed: Evolution has one at 0x82237130.
    case PPC_INST_MULHD:
        println("\t{}.s64 = int64_t((__int128_t({}.s64) * __int128_t({}.s64)) >> 64);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int64_t>({}.s64, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    // The 64-bit high half. This is how the compiler divides by a constant:
    // multiply by a reciprocal magic number and keep the top bits, so dropping
    // the instruction leaves the destination holding whatever it held before -
    // a plausible number, not a crash. Space Giraffe has one, dividing a
    // 64-bit tick count by 1000 (magic 0x0624DD2F1A9FBE77) at 0x820A81EC.
    case PPC_INST_MULHDU:
        println("\t{}.u64 = uint64_t((__uint128_t({}.u64) * __uint128_t({}.u64)) >> 64);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int64_t>({}.s64, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_MULLD:
        println("\t{}.s64 = {}.s64 * {}.s64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_MULLI:
        println("\t{}.s64 = {}.s64 * {};", r(insn.operands[0]), r(insn.operands[1]), int32_t(insn.operands[2]));
        break;

    case PPC_INST_MULLW:
        println("\t{}.s64 = int64_t({}.s32) * int64_t({}.s32);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_NAND:
        println("\t{}.u64 = ~({}.u64 & {}.u64);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_NEG:
        println("\t{}.s64 = -{}.s64;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_NOP:
        // no op
        break;

    case PPC_INST_NOR:
        println("\t{}.u64 = ~({}.u64 | {}.u64);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_NOT:
        println("\t{}.u64 = ~{}.u64;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_OR:
        println("\t{}.u64 = {}.u64 | {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ORC:
        println("\t{}.u64 = {}.u64 | ~{}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_ORI:
        println("\t{}.u64 = {}.u64 | {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        break;

    case PPC_INST_ORIS:
        println("\t{}.u64 = {}.u64 | {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2] << 16);
        break;

    case PPC_INST_RLDICL:
        println("\t{}.u64 = __builtin_rotateleft64({}.u64, {}) & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2], ComputeMask(insn.operands[3], 63));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int64_t>({}.s64, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_RLDICR:
        println("\t{}.u64 = __builtin_rotateleft64({}.u64, {}) & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2], ComputeMask(0, insn.operands[3]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int64_t>({}.s64, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_RLDIMI:
    {
        const uint64_t mask = ComputeMask(insn.operands[3], ~insn.operands[2]);
        println("\t{}.u64 = (__builtin_rotateleft64({}.u64, {}) & 0x{:X}) | ({}.u64 & 0x{:X});", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2], mask, r(insn.operands[0]), ~mask);
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int64_t>({}.s64, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;
    }

    case PPC_INST_RLWIMI:
    {
        const uint64_t mask = ComputeMask(insn.operands[3] + 32, insn.operands[4] + 32);
        println("\t{}.u64 = (__builtin_rotateleft32({}.u32, {}) & 0x{:X}) | ({}.u64 & 0x{:X});", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2], mask, r(insn.operands[0]), ~mask);
        break;
    }

    case PPC_INST_RLWINM:
        println("\t{}.u64 = __builtin_rotateleft64({}.u32 | ({}.u64 << 32), {}) & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[1]), insn.operands[2], ComputeMask(insn.operands[3] + 32, insn.operands[4] + 32));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ROTLDI:
        println("\t{}.u64 = __builtin_rotateleft64({}.u64, {});", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        break;

    case PPC_INST_ROTLW:
        println("\t{}.u64 = __builtin_rotateleft32({}.u32, {}.u8 & 0x1F);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_ROTLWI:
        println("\t{}.u64 = __builtin_rotateleft32({}.u32, {});", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SLD:
        println("\t{}.u64 = {}.u8 & 0x40 ? 0 : ({}.u64 << ({}.u8 & 0x7F));", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_SLW:
        println("\t{}.u64 = {}.u8 & 0x20 ? 0 : ({}.u32 << ({}.u8 & 0x3F));", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SRAD:
        println("\t{}.u64 = {}.u64 & 0x7F;", temp(), r(insn.operands[2]));
        println("\tif ({}.u64 > 0x3F) {}.u64 = 0x3F;", temp(), temp());
        println("\t{}.ca = ({}.s64 < 0) & ((({}.s64 >> {}.u64) << {}.u64) != {}.s64);", xer(), r(insn.operands[1]), r(insn.operands[1]), temp(), temp(), r(insn.operands[1]));
        println("\t{}.s64 = {}.s64 >> {}.u64;", r(insn.operands[0]), r(insn.operands[1]), temp());
        break;

    case PPC_INST_SRADI:
        if (insn.operands[2] != 0)
        {
            println("\t{}.ca = ({}.s64 < 0) & (({}.u64 & 0x{:X}) != 0);", xer(), r(insn.operands[1]), r(insn.operands[1]), ComputeMask(64 - insn.operands[2], 63));
            println("\t{}.s64 = {}.s64 >> {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        }
        else
        {
            println("\t{}.ca = 0;", xer());
            println("\t{}.s64 = {}.s64;", r(insn.operands[0]), r(insn.operands[1]));
        }
        break;

    case PPC_INST_SRAW:
        println("\t{}.u32 = {}.u32 & 0x3F;", temp(), r(insn.operands[2]));
        println("\tif ({}.u32 > 0x1F) {}.u32 = 0x1F;", temp(), temp());
        println("\t{}.ca = ({}.s32 < 0) & ((({}.s32 >> {}.u32) << {}.u32) != {}.s32);", xer(), r(insn.operands[1]), r(insn.operands[1]), temp(), temp(), r(insn.operands[1]));
        println("\t{}.s64 = {}.s32 >> {}.u32;", r(insn.operands[0]), r(insn.operands[1]), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SRAWI:
        if (insn.operands[2] != 0)
        {
            println("\t{}.ca = ({}.s32 < 0) & (({}.u32 & 0x{:X}) != 0);", xer(), r(insn.operands[1]), r(insn.operands[1]), ComputeMask(64 - insn.operands[2], 63));
            println("\t{}.s64 = {}.s32 >> {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        }
        else
        {
            println("\t{}.ca = 0;", xer());
            println("\t{}.s64 = {}.s32;", r(insn.operands[0]), r(insn.operands[1]));
        }
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SRD:
        println("\t{}.u64 = {}.u8 & 0x40 ? 0 : ({}.u64 >> ({}.u8 & 0x7F));", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_SRW:
        println("\t{}.u64 = {}.u8 & 0x20 ? 0 : ({}.u32 >> ({}.u8 & 0x3F));", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_STB:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U8(" : "\tPPC_STORE_U8(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u8);", int32_t(insn.operands[1]), r(insn.operands[0]));
        break;

    case PPC_INST_STBU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}{}, {}.u8);", mmioStore() ? "PPC_MM_STORE_U8(" : "PPC_STORE_U8(", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_STBX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U8(" : "\tPPC_STORE_U8(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u8);", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STBUX:
        println("\t{} = {}.u32 + {}.u32;", ea(), r(insn.operands[1]), r(insn.operands[2]));
        println("\t{}{}, {}.u8);", mmioStore() ? "PPC_MM_STORE_U8(" : "PPC_STORE_U8(", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[1]), ea());
        break;

    case PPC_INST_STD:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U64(" : "\tPPC_STORE_U64(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u64);", int32_t(insn.operands[1]), r(insn.operands[0]));
        break;

    case PPC_INST_STDCX:
        println("\t{}.lt = 0;", cr(0));
        println("\t{}.gt = 0;", cr(0));
        print("\t{}.eq = __sync_bool_compare_and_swap(reinterpret_cast<uint64_t*>(base + ", cr(0));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32), {}.s64, __builtin_bswap64({}.s64));", r(insn.operands[2]), reserved(), r(insn.operands[0]));
        println("\t{}.so = {}.so;", cr(0), xer());
        break;

    case PPC_INST_STDU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}{}, {}.u64);", mmioStore() ? "PPC_MM_STORE_U64(" : "PPC_STORE_U64(", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_STDX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U64(" : "\tPPC_STORE_U64(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u64);", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STDUX:
        println("\t{} = {}.u32 + {}.u32;", ea(), r(insn.operands[1]), r(insn.operands[2]));
        println("\t{}{}, {}.u64);", mmioStore() ? "PPC_MM_STORE_U64(" : "PPC_STORE_U64(", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[1]), ea());
        break;

    case PPC_INST_STFD:
        printSetFlushMode(false);
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U64(" : "\tPPC_STORE_U64(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u64);", int32_t(insn.operands[1]), f(insn.operands[0]));
        break;

    case PPC_INST_STFDU:
        printSetFlushMode(false);
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        // The mirror of the LFDU bug: operand 0 is the FPR being stored, so
        // r() here writes the same-numbered GPR's bits to memory instead of the
        // double. It does not corrupt a register, it silently stores the wrong
        // VALUE - which is worse to find later.
        println("\t{}{}, {}.u64);", mmioStore() ? "PPC_MM_STORE_U64(" : "PPC_STORE_U64(", ea(), f(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_STFDX:
        printSetFlushMode(false);
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U64(" : "\tPPC_STORE_U64(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u64);", r(insn.operands[2]), f(insn.operands[0]));
        break;

    case PPC_INST_STFIWX:
        printSetFlushMode(false);
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u32);", r(insn.operands[2]), f(insn.operands[0]));
        break;

    case PPC_INST_STFS:
        printSetFlushMode(false);
        println("\t{}.f32 = float({}.f64);", temp(), f(insn.operands[0]));
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u32);", int32_t(insn.operands[1]), temp());
        break;

    case PPC_INST_STFSU:
        printSetFlushMode(false);
        println("\t{}.f32 = float({}.f64);", temp(), f(insn.operands[0]));
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}{}, {}.u32);", mmioStore() ? "PPC_MM_STORE_U32(" : "PPC_STORE_U32(", ea(), temp());
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_STFSX:
        printSetFlushMode(false);
        println("\t{}.f32 = float({}.f64);", temp(), f(insn.operands[0]));
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u32);", r(insn.operands[2]), temp());
        break;

    case PPC_INST_STFSUX:
        printSetFlushMode(false);
        println("\t{}.f32 = float({}.f64);", temp(), f(insn.operands[0]));
        println("\t{} = {}.u32 + {}.u32;", ea(), r(insn.operands[1]), r(insn.operands[2]));
        println("\t{}{}, {}.u32);", mmioStore() ? "PPC_MM_STORE_U32(" : "PPC_STORE_U32(", ea(), temp());
        println("\t{}.u32 = {};", r(insn.operands[1]), ea());
        break;

    case PPC_INST_STH:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U16(" : "\tPPC_STORE_U16(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u16);", int32_t(insn.operands[1]), r(insn.operands[0]));
        break;

    case PPC_INST_STHU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}{}, {}.u16);", mmioStore() ? "PPC_MM_STORE_U16(" : "PPC_STORE_U16(", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_STHUX:
        println("\t{} = {}.u32 + {}.u32;", ea(), r(insn.operands[1]), r(insn.operands[2]));
        println("\t{}{}, {}.u16);", mmioStore() ? "PPC_MM_STORE_U16(" : "PPC_STORE_U16(", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[1]), ea());
        break;

    case PPC_INST_STHBRX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U16(" : "\tPPC_STORE_U16(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, __builtin_bswap16({}.u16));", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STHX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U16(" : "\tPPC_STORE_U16(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u16);", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STVEBX:
        // The effective-address low nibble selects the guest vector byte. The
        // runtime stores vectors fully reversed, so guest element 0 is u8[15].
        print("\t{} = ", ea());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));
        println("\tPPC_STORE_U8({}, {}.u8[15 - ({} & 0xF)]);", ea(), v(insn.operands[0]), ea());
        break;

    case PPC_INST_STVEHX:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\t{} = (", ea());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32) & ~0x1;", r(insn.operands[2]));
        println("\tPPC_STORE_U16(ea, {}.u16[7 - (({} & 0xF) >> 1)]);", v(insn.operands[0]), ea());
        break;

    case PPC_INST_STVEWX:
    case PPC_INST_STVEWX128:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\t{} = (", ea());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32) & ~0x3;", r(insn.operands[2]));
        println("\tPPC_STORE_U32(ea, {}.u32[3 - (({} & 0xF) >> 2)]);", v(insn.operands[0]), ea());
        break;

    case PPC_INST_STVLX:
    case PPC_INST_STVLX128:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\t{} = ", ea());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));

        println("\tfor (size_t i = 0; i < (16 - ({} & 0xF)); i++)", ea());
        println("\t\tPPC_STORE_U8({} + i, {}.u8[15 - i]);", ea(), v(insn.operands[0]));
        break;

    case PPC_INST_STVRX:
    case PPC_INST_STVRX128:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\t{} = ", ea());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));

        println("\tfor (size_t i = 0; i < ({} & 0xF); i++)", ea());
        println("\t\tPPC_STORE_U8({} - i - 1, {}.u8[i]);", ea(), v(insn.operands[0]));
        break;

    case PPC_INST_STVX:
    case PPC_INST_STVX128:
        print("\t_mm_store_si128((__m128i*)(base + ((");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32) & ~0xF)), _mm_shuffle_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*)VectorMaskL)));", r(insn.operands[2]), v(insn.operands[0]));
        break;

    case PPC_INST_STW:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u32);", int32_t(insn.operands[1]), r(insn.operands[0]));
        break;

    case PPC_INST_STWBRX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, __builtin_bswap32({}.u32));", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STWCX:
        println("\t{}.lt = 0;", cr(0));
        println("\t{}.gt = 0;", cr(0));
        print("\t{}.eq = __sync_bool_compare_and_swap(reinterpret_cast<uint32_t*>(base + ", cr(0));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32), {}.s32, __builtin_bswap32({}.s32));", r(insn.operands[2]), reserved(), r(insn.operands[0]));
        println("\t{}.so = {}.so;", cr(0), xer());
        break;

    case PPC_INST_STWU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}{}, {}.u32);", mmioStore() ? "PPC_MM_STORE_U32(" : "PPC_STORE_U32(", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_STWUX:
        println("\t{} = {}.u32 + {}.u32;", ea(), r(insn.operands[1]), r(insn.operands[2]));
        println("\t{}{}, {}.u32);", mmioStore() ? "PPC_MM_STORE_U32(" : "PPC_STORE_U32(", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[1]), ea());
        break;

    case PPC_INST_STWX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u32);", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_SUBF:
        println("\t{}.s64 = {}.s64 - {}.s64;", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SUBFC:
        println("\t{}.ca = {}.u32 >= {}.u32;", xer(), r(insn.operands[2]), r(insn.operands[1]));
        println("\t{}.s64 = {}.s64 - {}.s64;", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SUBFE:
        println("\t{}.u8 = (~{}.u32 + {}.u32 < ~{}.u32) | (~{}.u32 + {}.u32 + {}.ca < {}.ca);", temp(), r(insn.operands[1]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[1]), r(insn.operands[2]), xer(), xer());
        println("\t{}.u64 = ~{}.u64 + {}.u64 + {}.ca;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        println("\t{}.ca = {}.u8;", xer(), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SUBFZE:
        println("\t{}.u8 = (~{}.u32 < ~{}.u32) | (~{}.u32 + {}.ca < {}.ca);", temp(), r(insn.operands[1]), r(insn.operands[1]), r(insn.operands[1]), xer(), xer());
        println("\t{}.u64 = ~{}.u64 + {}.ca;", r(insn.operands[0]), r(insn.operands[1]), xer());
        println("\t{}.ca = {}.u8;", xer(), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SUBFIC:
        println("\t{}.ca = {}.u32 <= {};", xer(), r(insn.operands[1]), insn.operands[2]);
        println("\t{}.s64 = {} - {}.s64;", r(insn.operands[0]), int32_t(insn.operands[2]), r(insn.operands[1]));
        break;

    case PPC_INST_SYNC:
        // no op
        break;

    case PPC_INST_TDLGEI:
        // no op
        break;

    case PPC_INST_TDLLEI:
        // no op
        break;

    case PPC_INST_TWI:
        // no op
        break;

    case PPC_INST_TWLGEI:
        // no op
        break;

    case PPC_INST_TWLLEI:
        // no op
        break;

    case PPC_INST_VADDFP:
    case PPC_INST_VADDFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_add_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDSBS:
        println("\t_mm_store_si128((__m128i*){}.s8, _mm_adds_epi8(_mm_load_si128((__m128i*){}.s8), _mm_load_si128((__m128i*){}.s8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDSHS:
        println("\t_mm_store_si128((__m128i*){}.s16, _mm_adds_epi16(_mm_load_si128((__m128i*){}.s16), _mm_load_si128((__m128i*){}.s16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDSWS:
        // TODO: vectorize
        for (size_t i = 0; i < 4; i++)
        {
            println("\t{}.s64 = int64_t({}.s32[{}]) + int64_t({}.s32[{}]);", temp(), v(insn.operands[1]), i, v(insn.operands[2]), i);
            println("\t{}.s32[{}] = {}.s64 > INT_MAX ? INT_MAX : {}.s64 < INT_MIN ? INT_MIN : {}.s64;", v(insn.operands[0]), i, temp(), temp(), temp());
        }
        break;

    case PPC_INST_VADDUBM:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_add_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDUBS:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_adds_epu8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDUHM:
        println("\t_mm_store_si128((__m128i*){}.u16, _mm_add_epi16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDUWM:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_add_epi32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDUWS:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_adds_epu32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VAND:
    case PPC_INST_VAND128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_and_si128(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VANDC:
    case PPC_INST_VANDC128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_andnot_si128(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VAVGSB:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_avg_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VAVGSH:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_avg_epi16(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VAVGSW:
        // Signed rounded average: (a + b + 1) >> 1. Widen first so equal
        // INT_MAX/INT_MIN inputs cannot overflow before the shift.
        for (size_t i = 0; i < 4; i++)
            println("\t{}.s32[{}] = int32_t((int64_t({}.s32[{}]) + int64_t({}.s32[{}]) + 1) >> 1);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i);
        break;

    case PPC_INST_VAVGUB:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_avg_epu8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VAVGUH:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_avg_epu16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VCTSXS:
    case PPC_INST_VCFPSXWS128:
        printSetFlushMode(true);
        print("\t_mm_store_si128((__m128i*){}.s32, _mm_vctsxs(", v(insn.operands[0]));
        if (insn.operands[2] != 0)
            println("_mm_mul_ps(_mm_load_ps({}.f32), _mm_set1_ps({}))));", v(insn.operands[1]), 1u << insn.operands[2]);
        else
            println("_mm_load_ps({}.f32)));", v(insn.operands[1]));
        break;

    case PPC_INST_VCTUXS:
    case PPC_INST_VCFPUXWS128:
        printSetFlushMode(true);
        print("\t_mm_store_si128((__m128i*){}.u32, _mm_vctuxs(", v(insn.operands[0]));
        if (insn.operands[2] != 0)
            println("_mm_mul_ps(_mm_load_ps({}.f32), _mm_set1_ps({}))));", v(insn.operands[1]), 1u << insn.operands[2]);
        else
            println("_mm_load_ps({}.f32)));", v(insn.operands[1]));
        break;

    case PPC_INST_VCFSX:
    case PPC_INST_VCSXWFP128:
    {
        printSetFlushMode(true);
        print("\t_mm_store_ps({}.f32, ", v(insn.operands[0]));
        if (insn.operands[2] != 0)
        {
            const float value = ldexp(1.0f, -int32_t(insn.operands[2]));
            println("_mm_mul_ps(_mm_cvtepi32_ps(_mm_load_si128((__m128i*){}.u32)), _mm_castsi128_ps(_mm_set1_epi32(int(0x{:X})))));", v(insn.operands[1]), *reinterpret_cast<const uint32_t*>(&value));
        }
        else
        {
            println("_mm_cvtepi32_ps(_mm_load_si128((__m128i*){}.u32)));", v(insn.operands[1]));
        }
        break;
    }

    case PPC_INST_VCFUX:
    case PPC_INST_VCUXWFP128:
    {
        printSetFlushMode(true);
        print("\t_mm_store_ps({}.f32, ", v(insn.operands[0]));
        if (insn.operands[2] != 0)
        {
            const float value = ldexp(1.0f, -int32_t(insn.operands[2]));
            println("_mm_mul_ps(_mm_cvtepu32_ps_(_mm_load_si128((__m128i*){}.u32)), _mm_castsi128_ps(_mm_set1_epi32(int(0x{:X})))));", v(insn.operands[1]), *reinterpret_cast<const uint32_t*>(&value));
        }
        else
        {
            println("_mm_cvtepu32_ps_(_mm_load_si128((__m128i*){}.u32)));", v(insn.operands[1]));
        }
        break;
    }

    case PPC_INST_VCMPBFP:
    case PPC_INST_VCMPBFP128:
        // Vector Compare Bounds Floating Point: per element, bit 31 is set
        // when a > b and bit 30 when a < -b; a NaN in either operand sets
        // both. cmpnle/cmpnge are the NaN-including negations, so each AND
        // mask is exactly one bound's failure.
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_or_ps(_mm_and_ps(_mm_cmpnle_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)), _mm_castsi128_ps(_mm_set1_epi32(int(0x80000000)))), _mm_and_ps(_mm_cmpnge_ps(_mm_load_ps({}.f32), _mm_xor_ps(_mm_load_ps({}.f32), _mm_castsi128_ps(_mm_set1_epi32(int(0x80000000))))), _mm_castsi128_ps(_mm_set1_epi32(0x40000000)))));",
            v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
        {
            // The record form sets only CR6 bit 2: all elements in bounds,
            // i.e. the whole result is zero (both failure bits clear).
            println("\t{}.lt = 0;", cr(6));
            println("\t{}.gt = 0;", cr(6));
            println("\t{}.eq = _mm_movemask_epi8(_mm_cmpeq_epi32(_mm_load_si128((__m128i*){}.u32), _mm_setzero_si128())) == 0xFFFF;", cr(6), v(insn.operands[0]));
            println("\t{}.so = 0;", cr(6));
        }
        break;

    case PPC_INST_VCMPEQFP:
    case PPC_INST_VCMPEQFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_cmpeq_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_ps({}.f32), 0xF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPEQUB:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_cmpeq_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_si128((__m128i*){}.u8), 0xFFFF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPEQUH:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_cmpeq_epi16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_si128((__m128i*){}.u16), 0xFFFF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPEQUW:
    case PPC_INST_VCMPEQUW128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_cmpeq_epi32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_ps({}.f32), 0xF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPGEFP:
    case PPC_INST_VCMPGEFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_cmpge_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_ps({}.f32), 0xF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPGTFP:
    case PPC_INST_VCMPGTFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_cmpgt_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_ps({}.f32), 0xF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPGTUB:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_cmpgt_epu8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_si128((__m128i*){}.u8), 0xFFFF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPGTUH:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_cmpgt_epu16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_si128((__m128i*){}.u16), 0xFFFF);", cr(6), v(insn.operands[0]));
        break;

    // UNSIGNED word compare. The signed VCMPGTSW below cannot stand in: with
    // the top bit set the two disagree on every such word, and the result here
    // feeds a mask rather than a value, so a wrong lane is silent.
    case PPC_INST_VCMPGTUW:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_cmpgt_epu32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_si128((__m128i*){}.u32), 0xFFFF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPGTSH:
        println("\t_mm_store_si128((__m128i*){}.s8, _mm_cmpgt_epi16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_si128((__m128i*){}.s16), 0xFFFF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPGTSW:
        println("\t_mm_store_si128((__m128i*){}.s8, _mm_cmpgt_epi32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_si128((__m128i*){}.s32), 0xFFFF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VEXPTEFP:
    case PPC_INST_VEXPTEFP128:
        // TODO: vectorize
        printSetFlushMode(true);
        for (size_t i = 0; i < 4; i++)
            println("\t{}.f32[{}] = exp2f({}.f32[{}]);", v(insn.operands[0]), i, v(insn.operands[1]), i);
        break;

    case PPC_INST_VLOGEFP:
    case PPC_INST_VLOGEFP128:
        // TODO: vectorize
        printSetFlushMode(true);
        for (size_t i = 0; i < 4; i++)
            println("\t{}.f32[{}] = log2f({}.f32[{}]);", v(insn.operands[0]), i, v(insn.operands[1]), i);
        break;

    case PPC_INST_VMADDCFP128:
    case PPC_INST_VMADDFP:
    case PPC_INST_VMADDFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_add_ps(_mm_mul_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), v(insn.operands[3]));
        break;

    case PPC_INST_VMAXFP:
    case PPC_INST_VMAXFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_max_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMAXSH:
        println("\t_mm_store_si128((__m128i*){}.u16, _mm_max_epi16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMAXSW:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_max_epi32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMINSH:
        println("\t_mm_store_si128((__m128i*){}.u16, _mm_min_epi16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMINSW:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_min_epi32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    // UNSIGNED word minimum. Distinct from VMINSW rather than a spelling of
    // it: 0xFFFFFFFF is the largest value here and the smallest there, so
    // reusing _mm_min_epi32 would return the wrong operand for any word with
    // the top bit set.
    case PPC_INST_VMINUW:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_min_epu32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMINFP:
    case PPC_INST_VMINFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_min_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMRGHB:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_unpackhi_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGHH:
        println("\t_mm_store_si128((__m128i*){}.u16, _mm_unpackhi_epi16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGHW:
    case PPC_INST_VMRGHW128:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_unpackhi_epi32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGLB:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_unpacklo_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGLH:
        println("\t_mm_store_si128((__m128i*){}.u16, _mm_unpacklo_epi16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGLW:
    case PPC_INST_VMRGLW128:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_unpacklo_epi32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMSUM3FP128:
        // NOTE: accounting for full vector reversal here. should dot product yzw instead of xyz
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_dp_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32), 0xEF));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMSUM4FP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_dp_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32), 0xFF));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMULFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_mul_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VNMSUBFP:
    case PPC_INST_VNMSUBFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_xor_ps(_mm_sub_ps(_mm_mul_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)), _mm_load_ps({}.f32)), _mm_castsi128_ps(_mm_set1_epi32(int(0x80000000)))));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), v(insn.operands[3]));
        break;

    // ~(a | b). With both source registers the same it is the compiler's way of
    // spelling "bitwise not", which is how it is nearly always used - so that
    // case skips the redundant or.
    case PPC_INST_VNOR:
    case PPC_INST_VNOR128:
        print("\t_mm_store_si128((__m128i*){}.u8, _mm_xor_si128(", v(insn.operands[0]));

        if (insn.operands[1] != insn.operands[2])
            println("_mm_or_si128(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)), _mm_set1_epi32(-1)));", v(insn.operands[1]), v(insn.operands[2]));
        else
            println("_mm_load_si128((__m128i*){}.u8), _mm_set1_epi32(-1)));", v(insn.operands[1]));

        break;

    case PPC_INST_VOR:
    case PPC_INST_VOR128:
        print("\t_mm_store_si128((__m128i*){}.u8, ", v(insn.operands[0]));

        if (insn.operands[1] != insn.operands[2])
            println("_mm_or_si128(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[1]), v(insn.operands[2]));
        else
            println("_mm_load_si128((__m128i*){}.u8));", v(insn.operands[1]));

        break;

    case PPC_INST_VPERM:
    case PPC_INST_VPERM128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_perm_epi8_(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), v(insn.operands[3]));
        break;

    case PPC_INST_VPERMWI128:
    {
        // NOTE: accounting for full vector reversal here
        uint32_t x = 3 - (insn.operands[2] & 0x3);
        uint32_t y = 3 - ((insn.operands[2] >> 2) & 0x3);
        uint32_t z = 3 - ((insn.operands[2] >> 4) & 0x3);
        uint32_t w = 3 - ((insn.operands[2] >> 6) & 0x3);
        uint32_t perm = x | (y << 2) | (z << 4) | (w << 6);
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_shuffle_epi32(_mm_load_si128((__m128i*){}.u32), 0x{:X}));", v(insn.operands[0]), v(insn.operands[1]), perm);
        break;
    }

    case PPC_INST_VPKD3D128:
        // TODO: vectorize somehow?
        // NOTE: handling vector reversal here too
        printSetFlushMode(true);
        switch (insn.operands[2])
        {
        case 0: // D3D color
            if (insn.operands[3] != 1)
                fmt::println("Unexpected D3D color pack instruction at {:X}", base);

            for (size_t i = 0; i < 4; i++)
            {
                constexpr size_t indices[] = { 3, 0, 1, 2 };
                println("\t{}.u32[{}] = 0x404000FF;", vTemp(), i);
                println("\t{}.f32[{}] = {}.f32[{}] < 3.0f ? 3.0f : ({}.f32[{}] > {}.f32[{}] ? {}.f32[{}] : {}.f32[{}]);", vTemp(), i, v(insn.operands[1]), i, v(insn.operands[1]), i, vTemp(), i, vTemp(), i, v(insn.operands[1]), i);
                println("\t{}.u32 {}= uint32_t({}.u8[{}]) << {};", temp(), i == 0 ? "" : "|", vTemp(), i * 4, indices[i] * 8);
            }
            println("\t{}.u32[{}] = {}.u32;", v(insn.operands[0]), insn.operands[4], temp());
            break;

        case 2: // 2_10_10_10 (VPACK_NORMPACKED32, DXGI_FORMAT_R10G10B10A2)
            if (insn.operands[3] != 1)
                fmt::println("Unexpected 2_10_10_10 pack instruction at {:X}", base);

            // The Xenos pack reads the low mantissa bits of floats the game
            // has pre-biased into a narrow window around 3.0: clamp into the
            // window, then mask the bits. XYZ are the signed-10-bit
            // components, W the unsigned-2-bit one (Xenia's
            // XMMPackUINT_2101010_* constants, x64_emitter.cc). Lanes are
            // reversed here, so guest x y z w live at .f32[3..0].
            //
            // The compares are ordered max-then-min so a NaN source packs as
            // the window minimum, matching vmaxps/vminps on a NaN operand.
            for (size_t i = 0; i < 4; i++)
            {
                const char* minC = i == 0 ? "3.0f" : "2.999878168106079f";
                const char* maxC = i == 0 ? "3.0000007152557373f"
                                          : "3.000121831893921f";
                println("\t{}.f32[{}] = {}.f32[{}] >= {} ? {}.f32[{}] : {};",
                        vTemp(), i, v(insn.operands[1]), i, minC,
                        v(insn.operands[1]), i, minC);
                println("\t{}.f32[{}] = {}.f32[{}] <= {} ? {}.f32[{}] : {};",
                        vTemp(), i, vTemp(), i, maxC, vTemp(), i, maxC);
            }
            // w<<30 | z<<20 | y<<10 | x, from lanes 0,1,2,3 respectively.
            println("\t{}.u32 = (({}.u32[0] & 0x3u) << 30) | (({}.u32[1] & 0x3FFu) << 20) | (({}.u32[2] & 0x3FFu) << 10) | ({}.u32[3] & 0x3FFu);",
                    temp(), vTemp(), vTemp(), vTemp(), vTemp());
            println("\t{}.u32[{}] = {}.u32;", v(insn.operands[0]),
                    insn.operands[4], temp());
            break;

        case 3: // float16_2 (VPACK_FLOAT16_2, D3D R16G16_FLOAT)
            if (insn.operands[3] != 1)
                fmt::println("Unexpected float16_2 pack instruction at {:X}", base);

            // Packs source x and y (u32[3] and u32[2] in this reversed
            // layout) to half floats forming ((half)x << 16) | (half)y, and
            // replaces only destination word [operands[4]] - the same
            // VPACK_32 placement rule the D3D color case above uses. The two
            // halves are assembled in vTemp.u32[3] (u8[0] is the per-element
            // exponent scratch, so word 0 is off limits) and stored once,
            // which also keeps a source-aliasing destination safe.
            for (size_t i = 0; i < 2; i++)
            {
                const size_t src = 3 - i;   // x then y
                const size_t out = 7 - i;   // vTemp.u16 high then low of u32[3]
                // Same conversion as the float16_4 case below.
                println("\t{}.u32 = ({}.u32[{}]&0x7FFFFFFF);", temp(), v(insn.operands[1]), src);
                println("\t{0}.u8[0] = ({1}.f32 != {1}.f32) || ({1}.f32 > 65504.0f) ? 0xFF : (({2}.u32[{3}]&0x7f800000)>>23);", vTemp(), temp(), v(insn.operands[1]), src);
                println("\t{}.u16 = {}.u8[0] != 0xFF ? (({}.u32[{}]&0x7FE000)>>13) : 0x0;", temp(), vTemp(), v(insn.operands[1]), src);
                println("\t{0}.u16[{1}] = {0}.u8[0] != 0xFF ? ({0}.u8[0] > 0x70 ? ((({0}.u8[0]-0x70)<<10)+{2}.u16) : (0x71-{0}.u8[0] > 31 ? 0x0 : ((0x400+{2}.u16)>>(0x71-{0}.u8[0])))) : 0x7FFF;", vTemp(), out, temp());
                println("\t{}.u16[{}] |= (({}.u32[{}]&0x80000000)>>16);", vTemp(), out, v(insn.operands[1]), src);
            }
            println("\t{}.u32[{}] = {}.u32[3];", v(insn.operands[0]), insn.operands[4], vTemp());
            break;

        case 5: // float16_4
            if (insn.operands[3] != 2 || insn.operands[4] > 2)
                fmt::println("Unexpected float16_4 pack instruction at {:X}", base);

            for (size_t i = 0; i < 4; i++)
            {
        		// Strip sign from source
        		println("\t{}.u32 = ({}.u32[{}]&0x7FFFFFFF);", temp(), v(insn.operands[1]), i);
        		// If |source| is > 65504, clamp output to 0x7FFF, else save 8 exponent bits 
        		println("\t{0}.u8[0] = ({1}.f32 != {1}.f32) || ({1}.f32 > 65504.0f) ? 0xFF : (({2}.u32[{3}]&0x7f800000)>>23);", vTemp(), temp(), v(insn.operands[1]), i);
        		// If 8 exponent bits were saved, it can only be 0x8E at most
        		// If saved, save first 10 bits of mantissa
        		println("\t{}.u16 = {}.u8[0] != 0xFF ? (({}.u32[{}]&0x7FE000)>>13) : 0x0;", temp(), vTemp(), v(insn.operands[1]), i);
        		// If saved and > 127-15, exponent is converted from 8 to 5-bit by subtracting 0x70
        		// If saved but not > 127-15, clamp exponent at 0, add 0x400 to mantissa and shift right by (0x71-exponent)
        		// If right shift is greater than 31 bits, manually clamp mantissa to 0 or else the output of the shift will be wrong
        		println("\t{0}.u16[{1}] = {2}.u8[0] != 0xFF ? ({2}.u8[0] > 0x70 ? ((({2}.u8[0]-0x70)<<10)+{3}.u16) : (0x71-{2}.u8[0] > 31 ? 0x0 : ((0x400+{3}.u16)>>(0x71-{2}.u8[0])))) : 0x7FFF;", v(insn.operands[0]), i+(2*insn.operands[4]), vTemp(), temp());
        		// Add back original sign
        		println("\t{}.u16[{}] |= (({}.u32[{}]&0x80000000)>>16);", v(insn.operands[0]), i+(2*insn.operands[4]), v(insn.operands[1]), i);
            }
            break;

        default:
            println("\t__builtin_debugtrap();");
            break;
        }
        break;

    case PPC_INST_VPKSHSS:
    case PPC_INST_VPKSHSS128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_packs_epi16(_mm_load_si128((__m128i*){}.s16), _mm_load_si128((__m128i*){}.s16)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VPKSWSS:
    case PPC_INST_VPKSWSS128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_packs_epi32(_mm_load_si128((__m128i*){}.s32), _mm_load_si128((__m128i*){}.s32)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VPKSHUS:
    case PPC_INST_VPKSHUS128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_packus_epi16(_mm_load_si128((__m128i*){}.s16), _mm_load_si128((__m128i*){}.s16)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VPKSWUS:
    case PPC_INST_VPKSWUS128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_packus_epi32(_mm_load_si128((__m128i*){}.s32), _mm_load_si128((__m128i*){}.s32)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VPKUHUS:
    case PPC_INST_VPKUHUS128:
        for (size_t i = 0; i < 8; i++)
        {
            println("\t{0}.u8[{1}] = {2}.u16[{1}] > UCHAR_MAX ? UCHAR_MAX : {2}.u16[{1}];", vTemp(), i, v(insn.operands[2]));
            println("\t{0}.u8[{1}] = {2}.u16[{3}] > UCHAR_MAX ? UCHAR_MAX : {2}.u16[{3}];", vTemp(), i + 8, v(insn.operands[1]), i);
        }
        println("{} = {};", v(insn.operands[0]), vTemp());
        break;

    // Word -> halfword with UNSIGNED source saturation, so 0xFFFFFFFF becomes
    // 0xFFFF. _mm_packus_epi32 cannot be used for it: that reads its input as
    // signed and would clamp the same word to 0. Written out element by
    // element exactly as VPKUHUS is, one size up.
    case PPC_INST_VPKUWUS:
    case PPC_INST_VPKUWUS128:
        for (size_t i = 0; i < 4; i++)
        {
            println("\t{0}.u16[{1}] = {2}.u32[{1}] > USHRT_MAX ? USHRT_MAX : {2}.u32[{1}];", vTemp(), i, v(insn.operands[2]));
            println("\t{0}.u16[{1}] = {2}.u32[{3}] > USHRT_MAX ? USHRT_MAX : {2}.u32[{3}];", vTemp(), i + 4, v(insn.operands[1]), i);
        }
        println("{} = {};", v(insn.operands[0]), vTemp());
        break;

    // Halfword -> byte MODULO, which truncates rather than saturating: 0x01FF
    // becomes 0xFF, where VPKUHUS would also give 0xFF but 0x0100 becomes 0x00
    // here and 0xFF there. Element by element in the same operand order as
    // VPKUHUS - vB fills the low half, vA the high - with the clamp removed
    // rather than replaced, because the truncation IS the instruction.
    case PPC_INST_VPKUHUM:
    case PPC_INST_VPKUHUM128:
        for (size_t i = 0; i < 8; i++)
        {
            println("\t{0}.u8[{1}] = uint8_t({2}.u16[{1}]);", vTemp(), i, v(insn.operands[2]));
            println("\t{0}.u8[{1}] = uint8_t({2}.u16[{3}]);", vTemp(), i + 8, v(insn.operands[1]), i);
        }
        println("{} = {};", v(insn.operands[0]), vTemp());
        break;

    // Word -> halfword MODULO, which truncates rather than saturating:
    // 0x0001FFFF becomes 0xFFFF, where VPKUWUS would clamp. Same operand order
    // as VPKUHUM one size up - vB fills the low half, vA the high - with the
    // clamp removed rather than replaced, because the truncation IS the
    // instruction.
    case PPC_INST_VPKUWUM:
    case PPC_INST_VPKUWUM128:
        for (size_t i = 0; i < 4; i++)
        {
            println("\t{0}.u16[{1}] = uint16_t({2}.u32[{1}]);", vTemp(), i, v(insn.operands[2]));
            println("\t{0}.u16[{1}] = uint16_t({2}.u32[{3}]);", vTemp(), i + 4, v(insn.operands[1]), i);
        }
        println("{} = {};", v(insn.operands[0]), vTemp());
        break;

    case PPC_INST_VREFP:
    case PPC_INST_VREFP128:
        // TODO: see if we can use rcp safely
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_div_ps(_mm_set1_ps(1), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VRFIM:
    case PPC_INST_VRFIM128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_round_ps(_mm_load_ps({}.f32), _MM_FROUND_TO_NEG_INF | _MM_FROUND_NO_EXC));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VRFIN:
    case PPC_INST_VRFIN128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_round_ps(_mm_load_ps({}.f32), _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VRFIP:
    case PPC_INST_VRFIP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_round_ps(_mm_load_ps({}.f32), _MM_FROUND_TO_POS_INF | _MM_FROUND_NO_EXC));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VRFIZ:
    case PPC_INST_VRFIZ128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_round_ps(_mm_load_ps({}.f32), _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VRLIMI128:
    {
        constexpr size_t shuffles[] = { _MM_SHUFFLE(3, 2, 1, 0), _MM_SHUFFLE(2, 1, 0, 3), _MM_SHUFFLE(1, 0, 3, 2), _MM_SHUFFLE(0, 3, 2, 1) };
        println("\t_mm_store_ps({}.f32, _mm_blend_ps(_mm_load_ps({}.f32), _mm_permute_ps(_mm_load_ps({}.f32), {}), {}));", v(insn.operands[0]), v(insn.operands[0]), v(insn.operands[1]), shuffles[insn.operands[3]], insn.operands[2]);
        break;
    }

    case PPC_INST_VRLH:
        for (size_t i = 0; i < 8; i++)
        {
            println("\t{0}.u16[{1}] = ({2}.u16[{1}] << ({3}.u16[{1}] & 0xF)) | ({2}.u16[{1}] >> (16 - ({3}.u16[{1}] & 0xF)));", vTemp(), i, v(insn.operands[1]), v(insn.operands[2]));
        }
        println("{} = {};", v(insn.operands[0]), vTemp());
        break;

    case PPC_INST_VRSQRTEFP:
    case PPC_INST_VRSQRTEFP128:
        // TODO: see if we can use rsqrt safely
        // TODO: we can detect if the input is from a dot product and apply logic only on one value
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_div_ps(_mm_set1_ps(1), _mm_sqrt_ps(_mm_load_ps({}.f32))));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VSEL:
    case PPC_INST_VSEL128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_or_si128(_mm_andnot_si128(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)), _mm_and_si128(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8))));", v(insn.operands[0]), v(insn.operands[3]), v(insn.operands[1]), v(insn.operands[3]), v(insn.operands[2]));
        break;

    case PPC_INST_VSLB:
        // TODO: vectorize
        for (size_t i = 0; i < 16; i++)
            println("\t{}.u8[{}] = {}.u8[{}] << ({}.u8[{}] & 0x7);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i);
        break;

    case PPC_INST_VSLH:
        // TODO: vectorize
        for (size_t i = 0; i < 8; i++)
            println("\t{}.u16[{}] = {}.u16[{}] << ({}.u8[{}] & 0xF);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i * 2);
        break;

    case PPC_INST_VSLDOI:
    case PPC_INST_VSLDOI128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_alignr_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8), {}));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), 16 - insn.operands[3]);
        break;

    case PPC_INST_VSLO:
    case PPC_INST_VSLO128:
        // Shift the WHOLE vector left by whole octets, zero-filling from the
        // right - not a per-element shift like the VSLB/VSLH/VSLW family above,
        // so the vector reversal every load performs has to be accounted for.
        //
        // The guest count is bits 121:124 of vB, which is bits 1:4 of its
        // lowest-order byte - `(VB.b[F] & 0x78) >> 3` as Xenia writes it
        // (ppc_emit_altivec.cc, InstrEmit_vslo_). Guest byte 15 is u8[0] here.
        //
        // Guest result byte i is vA byte i+sh; with host index h = 15-i that is
        // vA host byte h-sh, so it stays a left shift in host element order.
        // Zero fill happens where h < sh; the index is masked so the untaken
        // arm of the select can never name a byte outside the register.
        //
        // vTemp because the destination is very often also vA, and this reads
        // lower host indices than it writes.
        println("\t{}.u32 = ({}.u8[0] >> 3) & 0xF;", temp(), v(insn.operands[2]));
        for (size_t i = 0; i < 16; i++)
            println("\t{}.u8[{}] = {} >= {}.u32 ? {}.u8[({} - {}.u32) & 0xF] : 0;", vTemp(), i, i, temp(), v(insn.operands[1]), i, temp());
        println("\t{} = {};", v(insn.operands[0]), vTemp());
        break;

    case PPC_INST_VSRO:
    case PPC_INST_VSRO128:
        // The mirror of VSLO above: shift the WHOLE vector right by whole
        // octets, zero-filling from the left. Same reasoning about the vector
        // reversal every load performs, run the other way.
        //
        // The guest count is read identically - bits 121:124 of vB, i.e. bits
        // 1:4 of its lowest-order byte, which is u8[0] here (Xenia's
        // InstrEmit_vsro_ in ppc_emit_altivec.cc).
        //
        // Guest result byte i is vA byte i-sh; with host index h = 15-i that is
        // vA host byte h+sh, so it stays a right shift in host element order.
        // Zero fill happens where h+sh > 15; as with VSLO the index is masked
        // so the untaken arm of the select can never name a byte outside the
        // register.
        //
        // vTemp because the destination is very often also vA, and this reads
        // higher host indices than it writes.
        println("\t{}.u32 = ({}.u8[0] >> 3) & 0xF;", temp(), v(insn.operands[2]));
        for (size_t i = 0; i < 16; i++)
            println("\t{}.u8[{}] = {} + {}.u32 <= 15 ? {}.u8[({} + {}.u32) & 0xF] : 0;", vTemp(), i, i, temp(), v(insn.operands[1]), i, temp());
        println("\t{} = {};", v(insn.operands[0]), vTemp());
        break;

    case PPC_INST_VSLW:
    case PPC_INST_VSLW128:
        // TODO: vectorize, ensure endianness is correct
        for (size_t i = 0; i < 4; i++)
            println("\t{}.u32[{}] = {}.u32[{}] << ({}.u8[{}] & 0x1F);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i * 4);
        break;

    case PPC_INST_VSPLTB:
    {
        // NOTE: accounting for full vector reversal here
        uint32_t perm = 15 - insn.operands[2];
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_shuffle_epi8(_mm_load_si128((__m128i*){}.u8), _mm_set1_epi8(char(0x{:X}))));", v(insn.operands[0]), v(insn.operands[1]), perm);
        break;
    }

    case PPC_INST_VSPLTH:
    {
        // NOTE: accounting for full vector reversal here
        uint32_t perm = 7 - insn.operands[2];
        perm = (perm * 2) | ((perm * 2 + 1) << 8);
        println("\t_mm_store_si128((__m128i*){}.u16, _mm_shuffle_epi8(_mm_load_si128((__m128i*){}.u16), _mm_set1_epi16(short(0x{:X}))));", v(insn.operands[0]), v(insn.operands[1]), perm);
        break;
    }

    case PPC_INST_VSPLTISB:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_set1_epi8(char(0x{:X})));", v(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_VSPLTISH:
        println("\t_mm_store_si128((__m128i*){}.u16, _mm_set1_epi16(int(0x{:X})));", v(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_VSPLTISW:
    case PPC_INST_VSPLTISW128:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_set1_epi32(int(0x{:X})));", v(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_VSPLTW:
    case PPC_INST_VSPLTW128:
    {
        // NOTE: accounting for full vector reversal here
        uint32_t perm = 3 - insn.operands[2];
        perm |= (perm << 2) | (perm << 4) | (perm << 6);
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_shuffle_epi32(_mm_load_si128((__m128i*){}.u32), 0x{:X}));", v(insn.operands[0]), v(insn.operands[1]), perm);
        break;
    }

    case PPC_INST_VSR:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_vsr(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSRAB:
        // TODO: vectorize, ensure endianness is correct
        for (size_t i = 0; i < 16; i++)
            println("\t{}.s8[{}] = {}.s8[{}] >> ({}.u8[{}] & 0x7);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i);
        break;

    case PPC_INST_VSRAH:
        // TODO: vectorize, ensure endianness is correct
        for (size_t i = 0; i < 8; i++)
            println("\t{}.s16[{}] = {}.s16[{}] >> ({}.u8[{}] & 0xF);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i * 2);
        break;

    case PPC_INST_VSRAW:
    case PPC_INST_VSRAW128:
        // TODO: vectorize, ensure endianness is correct
        for (size_t i = 0; i < 4; i++)
            println("\t{}.s32[{}] = {}.s32[{}] >> ({}.u8[{}] & 0x1F);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i * 4);
        break;

    case PPC_INST_VSRH:
        // TODO: vectorize, ensure endianness is correct
        for (size_t i = 0; i < 8; i++)
            println("\t{}.u16[{}] = {}.u16[{}] >> ({}.u8[{}] & 0xF);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i * 2);
        break;

    case PPC_INST_VSRW:
    case PPC_INST_VSRW128:
        // TODO: vectorize, ensure endianness is correct
        for (size_t i = 0; i < 4; i++)
            println("\t{}.u32[{}] = {}.u32[{}] >> ({}.u8[{}] & 0x1F);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i * 4);
        break;

    case PPC_INST_VSUBFP:
    case PPC_INST_VSUBFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_sub_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSUBSBS:
        // Signed saturating byte subtract, which is exactly _mm_subs_epi8.
        // Element-wise, so the whole-vector reversal is irrelevant here - the
        // same reason VSUBUBS just below can use _mm_subs_epu8 directly.
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_subs_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSUBSHS:
        // TODO: vectorize
        for (size_t i = 0; i < 8; i++)
        {
            println("\t{}.s64 = int64_t({}.s16[{}]) - int64_t({}.s16[{}]);", temp(), v(insn.operands[1]), i, v(insn.operands[2]), i);
            println("\t{}.s16[{}] = {}.s64 > SHRT_MAX ? SHRT_MAX : {}.s64 < SHRT_MIN ? SHRT_MIN : {}.s64;", v(insn.operands[0]), i, temp(), temp(), temp());
        }
        break;

    case PPC_INST_VSUBSWS:
        // TODO: vectorize
        for (size_t i = 0; i < 4; i++)
        {
            println("\t{}.s64 = int64_t({}.s32[{}]) - int64_t({}.s32[{}]);", temp(), v(insn.operands[1]), i, v(insn.operands[2]), i);
            println("\t{}.s32[{}] = {}.s64 > INT_MAX ? INT_MAX : {}.s64 < INT_MIN ? INT_MIN : {}.s64;", v(insn.operands[0]), i, temp(), temp(), temp());
        }
        break;

    case PPC_INST_VSUBUBS:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_subs_epu8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSUBUBM:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_sub_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSUBUHM:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_sub_epi16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VUPKD3D128:
        // TODO: vectorize somehow?
        // NOTE: handling vector reversal here too
        switch (insn.operands[2] >> 2)
        {
        case 0: // D3D color
            for (size_t i = 0; i < 4; i++)
            {
                constexpr size_t indices[] = { 3, 0, 1, 2 };
                println("\t{}.u32[{}] = {}.u8[{}] | 0x3F800000;", vTemp(), i, v(insn.operands[1]), indices[i]);
            }
            println("\t{} = {};", v(insn.operands[0]), vTemp());
            break;

        case 1: // 2 shorts
            for (size_t i = 0; i < 2; i++)
            {
                println("\t{}.s32 = {}.s16[{}];", temp(), v(insn.operands[1]), 1 - i);
                println("\t{}.u32[{}] = {}.s32 == -32768 ? 0x7FC00000 : uint32_t({}.s32 + 0x40400000);", vTemp(), 3 - i, temp(), temp());
            }
            println("\t{}.f32[1] = 0.0f;", vTemp());
            println("\t{}.f32[0] = 1.0f;", vTemp());
            println("\t{} = {};", v(insn.operands[0]), vTemp());
            break;

        case 2: // packed 2:10:10:10 (signed XYZ, unsigned W)
            println("\t{}.u32 = {}.u32[0];", temp(), v(insn.operands[1]));
            for (size_t i = 0; i < 3; i++)
            {
                println("\t{}.s32[0] = int32_t({}.u32 << {}) >> 22;", vTemp(), temp(), 22 - i * 10);
                println("\t{}.u32[{}] = {}.s32[0] == -512 ? 0x7FC00000 : uint32_t({}.s32[0] + 0x40400000);", v(insn.operands[0]), 3 - i, vTemp(), vTemp());
            }
            println("\t{}.u32[0] = ({}.u32 >> 30) | 0x3F800000;", v(insn.operands[0]), temp());
            break;

        // The two half-float unpacks, matching Xenia's InstrEmit_vupkd3d128
        // types 3 (VPACK_FLOAT16_2) and 5 (VPACK_FLOAT16_4), and exactly
        // inverting the float16_4 case of VPKD3D128 above.
        //
        // The halves are XENOS half-floats, not IEEE binary16: exponent bias
        // 112 rather than 15, no infinity and no NaN, and denormals read as
        // zero (Xenia's xenos_half_to_float with preserve_denormal = false,
        // which is what vupkd3d128 uses). Decoding them as IEEE would be wrong
        // by a factor of 2^97 on every value that is not zero, which is the
        // kind of wrong that renders as geometry flung off to infinity rather
        // than as an obvious failure.
        //
        // Element order follows the reversal the rest of this case handles:
        // the vector is byte-reversed on load, so guest halfword k lives at
        // .u16[7 - k] and the guest's leftmost float x is .f32[3]. Working
        // that through, both unpacks read .u16[] and write .f32[] at matching
        // indices - the same correspondence the pack relies on.
        case 3: // 2 half floats
            for (size_t i = 0; i < 2; i++)
            {
                println("\t{}.u32 = {}.u16[{}];", temp(), v(insn.operands[1]), 1 - i);
                println("\t{}.u32[{}] = (({}.u32 & 0x8000) << 16) | ((({}.u32 & 0x7C00) != 0) ? (((((({}.u32 >> 10) & 0x1F) + 112) << 23) | (({}.u32 & 0x3FF) << 13))) : 0);", vTemp(), 3 - i, temp(), temp(), temp(), temp());
            }
            // The guest splats these after unpacking to get vectors of 1.0f,
            // so they are part of the instruction, not padding.
            println("\t{}.f32[1] = 0.0f;", vTemp());
            println("\t{}.f32[0] = 1.0f;", vTemp());
            println("\t{} = {};", v(insn.operands[0]), vTemp());
            break;

        case 4: // 4 shorts
            for (size_t i = 0; i < 4; i++)
            {
                println("\t{}.s32 = {}.s16[{}];", temp(), v(insn.operands[1]), 3 - i);
                println("\t{}.u32[{}] = {}.s32 == -32768 ? 0x7FC00000 : uint32_t({}.s32 + 0x40400000);", v(insn.operands[0]), 3 - i, temp(), temp());
            }
            break;

        case 5: // 4 half floats
            for (size_t i = 0; i < 4; i++)
            {
                println("\t{}.u32 = {}.u16[{}];", temp(), v(insn.operands[1]), i);
                println("\t{}.u32[{}] = (({}.u32 & 0x8000) << 16) | ((({}.u32 & 0x7C00) != 0) ? (((((({}.u32 >> 10) & 0x1F) + 112) << 23) | (({}.u32 & 0x3FF) << 13))) : 0);", vTemp(), i, temp(), temp(), temp(), temp());
            }
            println("\t{} = {};", v(insn.operands[0]), vTemp());
            break;

        case 6: // packed 4:20:20:20 (signed XYZ, unsigned W)
            println("\t{}.u64[0] = {}.u64[0];", vTemp(), v(insn.operands[1]));
            for (size_t i = 0; i < 3; i++)
            {
                println("\t{}.s32 = int32_t(int64_t({}.u64[0] << {}) >> 44);", temp(), vTemp(), 44 - i * 20);
                println("\t{}.u32[{}] = {}.s32 == -524288 ? 0x7FC00000 : uint32_t({}.s32 + 0x40400000);", v(insn.operands[0]), 3 - i, temp(), temp());
            }
            println("\t{}.u32[0] = uint32_t({}.u64[0] >> 60) | 0x3F800000;", v(insn.operands[0]), vTemp());
            break;

        default:
            println("\t__builtin_debugtrap();");
            break;
        }
        break;

    case PPC_INST_VUPKHSB:
    case PPC_INST_VUPKHSB128:
        println("\t_mm_store_si128((__m128i*){}.s16, _mm_cvtepi8_epi16(_mm_unpackhi_epi64(_mm_load_si128((__m128i*){}.s8), _mm_load_si128((__m128i*){}.s8))));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        break;

    case PPC_INST_VUPKHSH:
    case PPC_INST_VUPKHSH128:
        println("\t_mm_store_si128((__m128i*){}.s32, _mm_cvtepi16_epi32(_mm_unpackhi_epi64(_mm_load_si128((__m128i*){}.s16), _mm_load_si128((__m128i*){}.s16))));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        break;

    case PPC_INST_VUPKLSB:
    case PPC_INST_VUPKLSB128:
        println("\t_mm_store_si128((__m128i*){}.s32, _mm_cvtepi8_epi16(_mm_load_si128((__m128i*){}.s16)));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VUPKLSH:
    case PPC_INST_VUPKLSH128:
        println("\t_mm_store_si128((__m128i*){}.s32, _mm_cvtepi16_epi32(_mm_load_si128((__m128i*){}.s16)));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VXOR:
    case PPC_INST_VXOR128:
        print("\t_mm_store_si128((__m128i*){}.u8, ", v(insn.operands[0]));

        if (insn.operands[1] != insn.operands[2])
            println("_mm_xor_si128(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[1]), v(insn.operands[2]));
        else
            println("_mm_setzero_si128());");

        break;

    case PPC_INST_XOR:
        println("\t{}.u64 = {}.u64 ^ {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_XORI:
        println("\t{}.u64 = {}.u64 ^ {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        break;

    case PPC_INST_XORIS:
        println("\t{}.u64 = {}.u64 ^ {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2] << 16);
        break;

    default:
        return false;
    }

#if 1
    if (strchr(insn.opcode->name, '.'))
    {
        int lastLine = out.find_last_of('\n', out.size() - 2);
        if (out.find("cr0", lastLine + 1) == std::string::npos && out.find("cr6", lastLine + 1) == std::string::npos)
            fmt::println("{} at {:X} has RC bit enabled but no comparison was generated", insn.opcode->name, base);
    }
#endif

    if (midAsmHook != config.midAsmHooks.end() && midAsmHook->second.afterInstruction)
        printMidAsmHook();
    
    return true;
}

// "Runs off its end" means the function's last instruction neither branches nor
// returns, so control would continue into whatever follows. That is a real
// defect when analysis split a shared tail in two - but it is NOT a defect when
// the last instruction is a call to a routine that never comes back. The
// compiler emits no return after such a call because none can be reached, and
// what follows is alignment padding, not the rest of the function.
//
// RAINBOW ISLANDS TOWERING ADVENTURE! reports 54 of these and every one is that
// shape: a final `bl`, a single 0x00000000 padding word, then the next
// function's `mflr r12`. 42 of them call 82437218 and 5 call longjmp.
//
// A routine that never returns is one whose body contains no return
// instruction, which is a fact about the target that can simply be read. The
// check is deliberately conservative - an unknown target, or one whose extent
// is not known, is NOT excused - because the cost of being wrong here is a
// missing diagnostic on a genuinely truncated function.
bool Recompiler::EndsInCallThatNeverReturns(const ppc_insn& insn) const
{
    if (insn.opcode == nullptr || insn.opcode->id != PPC_INST_BL)
        return false;

    const uint32_t target = insn.operands[0];

    // longjmp is the unarguable case: it resumes at a setjmp, so it cannot
    // return to its caller, and it is already emitted as the host longjmp.
    if (config.longJmpAddress != 0 && target == config.longJmpAddress)
        return true;

    auto symbol = image.symbols.find(target);
    if (symbol == image.symbols.end() || symbol->address != target ||
        symbol->type != Symbol_Function || symbol->size < 4)
    {
        return false;
    }

    // An IMPORT cannot be judged by reading its body. The XEX loader replaces
    // every import thunk in the image with `nop nop nop blr` and does the real
    // work in the named __imp__ host function, so scanning the thunk finds a
    // return for every import there has ever been - including the ones that
    // terminate the thread.
    //
    // So imports are judged by name, and only where the name settles it. This
    // list is deliberately tiny: an export that merely USUALLY does not return
    // does not belong on it. RtlRaiseException is the obvious omission - an
    // exception handler may resume execution, so it can come back.
    static const char* const kNeverReturns[] = {
        "__imp__ExTerminateThread",
        "__imp__KeBugCheck",
        "__imp__KeBugCheckEx",
        "__imp__HalReturnToFirmware",
    };
    for (const char* name : kNeverReturns)
    {
        if (symbol->name == name)
            return true;
    }
    if (symbol->name.rfind("__imp__", 0) == 0)
        return false;

    const auto* code = (const uint32_t*)image.Find(target);
    if (code == nullptr)
        return false;

    // Any member of the branch-to-link-register family returns, including the
    // conditional ones (`beqlr` and friends), so scanning for the unconditional
    // `blr` encoding alone would call a routine no-return because its only exit
    // happens to be conditional.
    for (size_t offset = 0; offset < symbol->size; offset += 4)
    {
        const uint32_t instruction = ByteSwap(code[offset / 4]);
        if (PPC_OP(instruction) == 19 && ((instruction >> 1) & 0x3FF) == 16)
            return false;
    }

    return true;
}

bool Recompiler::Recompile(const Function& fn)
{
    auto base = fn.base;
    auto end = base + fn.size;
    auto* data = (uint32_t*)image.Find(base);

    static std::unordered_set<size_t> labels;
    labels.clear();

    for (size_t addr = base; addr < end; addr += 4)
    {
        const uint32_t instruction = ByteSwap(*(uint32_t*)((char*)data + addr - base));
        if (!PPC_BL(instruction))
        {
            const size_t op = PPC_OP(instruction);
            if (op == PPC_OP_B)
                labels.emplace(addr + PPC_BI(instruction));
            else if (op == PPC_OP_BC)
                labels.emplace(addr + PPC_BD(instruction));
        }

        auto switchTable = config.switchTables.find(addr);
        if (switchTable != config.switchTables.end())
        {
            for (auto label : switchTable->second.labels)
                labels.emplace(label);
        }

        auto midAsmHook = config.midAsmHooks.find(addr);
        if (midAsmHook != config.midAsmHooks.end())
        {
            if (midAsmHook->second.returnOnFalse || midAsmHook->second.returnOnTrue ||
                midAsmHook->second.jumpAddressOnFalse != NULL || midAsmHook->second.jumpAddressOnTrue != NULL)
            {
                print("extern bool ");
            }
            else
            {
                print("extern void ");
            }

            print("{}(", midAsmHook->second.name);
            for (auto& reg : midAsmHook->second.registers)
            {
                if (out.back() != '(')
                    out += ", ";

                switch (reg[0])
                {
                case 'c':
                    if (reg == "ctr")
                        print("PPCRegister& ctr");
                    else
                        print("PPCCRRegister& {}", reg);
                    break;

                case 'x':
                    print("PPCXERRegister& xer");
                    break;

                case 'r':
                    print("PPCRegister& {}", reg);
                    break;

                case 'f':
                    if (reg == "fpscr")
                        print("PPCFPSCRRegister& fpscr");
                    else
                        print("PPCRegister& {}", reg);
                    break;

                case 'v':
                    print("PPCVRegister& {}", reg);
                    break;
                }
            }

            println(");\n");

            if (midAsmHook->second.jumpAddress != NULL)
                labels.emplace(midAsmHook->second.jumpAddress);       
            if (midAsmHook->second.jumpAddressOnTrue != NULL)
                labels.emplace(midAsmHook->second.jumpAddressOnTrue);    
            if (midAsmHook->second.jumpAddressOnFalse != NULL)
                labels.emplace(midAsmHook->second.jumpAddressOnFalse);
        }
    }

    auto symbol = image.symbols.find(fn.base);
    std::string name;
    if (symbol != image.symbols.end())
    {
        name = symbol->name;
    }
    else
    {
        name = fmt::format("sub_{}", fn.base);
    }

#ifdef XENON_RECOMP_USE_ALIAS
    println("__attribute__((alias(\"__imp__{}\"))) PPC_WEAK_FUNC({});", name, name);
#endif

    println("PPC_FUNC_IMPL(__imp__{}) {{", name);
    println("\tPPC_FUNC_PROLOGUE();");

    auto switchTable = config.switchTables.end();
    bool allRecompiled = true;
    CSRState csrState = CSRState::Unknown;

    // TODO: the printing scheme here is scuffed
    RecompilerLocalVariables localVariables;
    static std::string tempString;
    tempString.clear();
    std::swap(out, tempString);

    // Zero-initialised because the "runs off its end" check below reads it, and
    // a function with no instructions never enters the loop that writes it.
    ppc_insn insn{};
    while (base < end)
    {
        if (labels.find(base) != labels.end())
        {
            println("loc_{:X}:", base);

            // Anyone could jump to this label so we wouldn't know what the CSR state would be.
            csrState = CSRState::Unknown;
        }

        if (switchTable == config.switchTables.end())
            switchTable = config.switchTables.find(base);

        ppc::Disassemble(data, 4, base, insn);

        if (insn.opcode == nullptr)
        {
            println("\t// {}", insn.op_str);
#if 1
            if (*data != 0)
                fmt::println("Unable to decode instruction {:X} at {:X}", *data, base);
#endif
        }
        else
        {
            if (insn.opcode->id == PPC_INST_BCTR && (*(data - 1) == 0x07008038 || *(data - 1) == 0x00000060) && switchTable == config.switchTables.end())
                fmt::println("Found a switch jump table at {:X} with no switch table entry present", base);

            if (!Recompile(fn, base, insn, data, switchTable, localVariables, csrState))
            {
                fmt::println("Unrecognized instruction at 0x{:X}: {}", base, insn.opcode->name);
                allRecompiled = false;
            }
        }

        base += 4;
        ++data;
    }

    // A function whose last instruction is not an unconditional branch or a
    // return does not end there - it runs straight on into whatever follows.
    //
    // That happens whenever the compiler gave several functions one shared
    // tail and analysis split them apart: the earlier half has no branch of
    // its own because it simply fell into the later half. Emitting nothing
    // here drops the rest of the computation silently - the function returns
    // with its result registers never written, which at runtime looks like a
    // feature that does nothing rather than like a bug. Tail-calling the code
    // that follows is what the hardware would have done.
    if (insn.opcode == nullptr || (insn.opcode->id != PPC_INST_B && insn.opcode->id != PPC_INST_BCTR && insn.opcode->id != PPC_INST_BLR))
    {
        auto nextSymbol = image.symbols.find(base);
        if (nextSymbol != image.symbols.end() && nextSymbol->address == base &&
            nextSymbol->type == Symbol_Function)
        {
            println("\t// fallthrough to {:X}", base);
            println("\t{}(ctx, base);", nextSymbol->name);
            println("\treturn;");
        }
        else if (!EndsInCallThatNeverReturns(insn))
        {
            fmt::println("Function at {:X} runs off its end at {:X} with nothing following it", fn.base, base);
        }
    }

    println("}}\n");

#ifndef XENON_RECOMP_USE_ALIAS
    println("PPC_WEAK_FUNC({}) {{", name);
    println("\t__imp__{}(ctx, base);", name);
    println("}}\n");
#endif

    std::swap(out, tempString);
    if (localVariables.ctr)
        println("\tPPCRegister ctr{{}};");   
    if (localVariables.xer)
        println("\tPPCXERRegister xer{{}};");
    if (localVariables.reserved)
        println("\tPPCRegister reserved{{}};");

    for (size_t i = 0; i < 8; i++)
    {
        if (localVariables.cr[i])
            println("\tPPCCRRegister cr{}{{}};", i);
    }

    for (size_t i = 0; i < 32; i++)
    {
        if (localVariables.r[i])
            println("\tPPCRegister r{}{{}};", i);
    }

    for (size_t i = 0; i < 32; i++)
    {
        if (localVariables.f[i])
            println("\tPPCRegister f{}{{}};", i);
    }

    for (size_t i = 0; i < 128; i++)
    {
        if (localVariables.v[i])
            println("\tPPCVRegister v{}{{}};", i);
    }

    if (localVariables.env)
        println("\tPPCContext env{{}};"); 
    
    if (localVariables.temp)
        println("\tPPCRegister temp{{}};"); 
    
    if (localVariables.vTemp)
        println("\tPPCVRegister vTemp{{}};");

    if (localVariables.ea)
        println("\tuint32_t ea{{}};");

    out += tempString;

    return allRecompiled;
}

void Recompiler::Recompile(const std::filesystem::path& headerFilePath)
{
    out.reserve(10 * 1024 * 1024);

    {
        println("#pragma once");

        println("#ifndef PPC_CONFIG_H_INCLUDED");
        println("#define PPC_CONFIG_H_INCLUDED\n");

        if (config.skipLr)
            println("#define PPC_CONFIG_SKIP_LR");      
        if (config.ctrAsLocalVariable)
            println("#define PPC_CONFIG_CTR_AS_LOCAL");      
        if (config.xerAsLocalVariable)
            println("#define PPC_CONFIG_XER_AS_LOCAL");      
        if (config.reservedRegisterAsLocalVariable)
            println("#define PPC_CONFIG_RESERVED_AS_LOCAL");      
        if (config.skipMsr)
            println("#define PPC_CONFIG_SKIP_MSR");      
        if (config.crRegistersAsLocalVariables)
            println("#define PPC_CONFIG_CR_AS_LOCAL");      
        if (config.nonArgumentRegistersAsLocalVariables)
            println("#define PPC_CONFIG_NON_ARGUMENT_AS_LOCAL");   
        if (config.nonVolatileRegistersAsLocalVariables)
            println("#define PPC_CONFIG_NON_VOLATILE_AS_LOCAL");

        println("");

        println("#define PPC_IMAGE_BASE 0x{:X}ull", image.base);
        println("#define PPC_IMAGE_SIZE 0x{:X}ull", image.size);
        
        // Extract the address of the minimum code segment to store the function table at.
        size_t codeMin = ~0;
        size_t codeMax = 0;

        for (auto& section : image.sections)
        {
            if ((section.flags & SectionFlags_Code) != 0)
            {
                if (section.base < codeMin)
                    codeMin = section.base;

                if ((section.base + section.size) > codeMax)
                    codeMax = (section.base + section.size);
            }
        }

        println("#define PPC_CODE_BASE 0x{:X}ull", codeMin);
        println("#define PPC_CODE_SIZE 0x{:X}ull", codeMax - codeMin);

        println("");

        println("#ifdef PPC_INCLUDE_DETAIL");
        println("#include \"ppc_detail.h\"");
        println("#endif");

        println("\n#endif");

        SaveCurrentOutData("ppc_config.h");
    }

    {
        println("#pragma once");

        println("#include \"ppc_config.h\"\n");
        
        std::ifstream stream(headerFilePath);
        if (stream.good())
        {
            std::stringstream ss;
            ss << stream.rdbuf();
            out += ss.str();
        }

        SaveCurrentOutData("ppc_context.h");
    }

    {
        println("#pragma once\n");
        println("#include \"ppc_config.h\"");
        println("#include \"ppc_context.h\"\n");

        for (auto& symbol : image.symbols)
            println("PPC_EXTERN_FUNC({});", symbol.name);

        SaveCurrentOutData("ppc_recomp_shared.h");
    }

    {
        println("#include \"ppc_recomp_shared.h\"\n");

        println("PPCFuncMapping PPCFuncMappings[] = {{");
        for (auto& symbol : image.symbols)
            println("\t{{ 0x{:X}, {} }},", symbol.address, symbol.name);

        println("\t{{ 0, nullptr }}");
        println("}};");

        SaveCurrentOutData("ppc_func_mapping.cpp");
    }

    for (size_t i = 0; i < functions.size(); i++)
    {
        if ((i % 256) == 0)
        {
            SaveCurrentOutData();
            println("#include \"ppc_recomp_shared.h\"\n");
        }

        if ((i % 2048) == 0 || (i == (functions.size() - 1)))
            fmt::println("Recompiling functions... {}%", static_cast<float>(i + 1) / functions.size() * 100.0f);

        Recompile(functions[i]);
    }

    SaveCurrentOutData();
}

void Recompiler::SaveCurrentOutData(const std::string_view& name)
{
    if (!out.empty())
    {
        std::string cppName;

        if (name.empty())
        {
            cppName = fmt::format("ppc_recomp.{}.cpp", cppFileIndex);
            ++cppFileIndex;
        }

        bool shouldWrite = true;

        // Check if an identical file already exists first to not trigger recompilation
        std::string directoryPath = config.directoryPath;
        if (!directoryPath.empty())
            directoryPath += "/";

        std::string filePath = fmt::format("{}{}/{}", directoryPath, config.outDirectoryPath, name.empty() ? cppName : name);
        FILE* f = fopen(filePath.c_str(), "rb");
        if (f)
        {
            static std::vector<uint8_t> temp;

            fseek(f, 0, SEEK_END);
            long fileSize = ftell(f);
            if (fileSize == out.size())
            {
                fseek(f, 0, SEEK_SET);
                temp.resize(fileSize);
                fread(temp.data(), 1, fileSize, f);

                shouldWrite = !XXH128_isEqual(XXH3_128bits(temp.data(), temp.size()), XXH3_128bits(out.data(), out.size()));
            }
            fclose(f);
        }

        if (shouldWrite)
        {
            f = fopen(filePath.c_str(), "wb");
            fwrite(out.data(), 1, out.size(), f);
            fclose(f);
        }

        out.clear();
    }
}
