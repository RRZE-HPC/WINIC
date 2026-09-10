#ifndef TEMPLATES_H
#define TEMPLATES_H

#include "Globals.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/TargetParser/Triple.h"
#include <list>
#include <set>
#include <string>

using std::string;

namespace winic {

struct RegInitTemplate {
    string templateString;
    unsigned targetRegisterClassID;
    std::optional<llvm::MCRegister> dependencyReg;

  public:
    string fillRegInitTemplate(llvm::MCRegister Reg, initType Imm);
};

/**
 * a template provides all code necessary in addition to the loop code to build an assembly file.
 * usedRegister contains all registers used by the template (like for the loop itself), that should
 * not be used inside the loop body.
 * regInitTemplates hold templates to initialize registers with a given value,
 */
struct Template {
    string prefix, preInit, postInit, preLoop, beginLoop, resetLoop, endLoop, postLoop, suffix;
    std::set<string> usedRegisters;
    std::list<RegInitTemplate> regInitTemplates;
    llvm::MCRegister bufferEndReg; // Register holding the end address of the scratch memory area
    string loadMemoryAddress; // Snippet loading the scratch memory area start address to a register

    Template(string Prefix, string PreInit, string PostInit, string PreLoop, string BeginLoop,
             string ResetLoop, string EndLoop, string PostLoop, string Suffix,
             std::set<string> UsedRegisters, std::list<RegInitTemplate> RegInitTemplates,
             llvm::MCRegister BufferEndReg, string LoadMemoryAddress);

    /**
     * \brief Generate an assembly snippet that executes ResetCode if the content of CompareReg is
     * greater or equal to the BufferEndReg. Used to reset memory base registers once they run past
     * the buffer end.
     * \param ResetCode Code to execute.
     * \param CompareReg Register to use for checking if a reset is necessary.
     * \return Assembly snippet
     */
    string genResetMemInLoopCode(string ResetCode, string CompareReg);

  private:
    void trimLeadingNewline(string &Str);
};

extern Template X86Template;
extern Template AArch64Template;
extern Template RISCVTemplate;

Template getTemplate();

} // namespace winic

#endif // TEMPLATES
