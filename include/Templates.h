#ifndef TEMPLATES_H
#define TEMPLATES_H

#include "llvm/MC/MCRegister.h"
#include "llvm/TargetParser/Triple.h"
#include <cstdint>
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
    template<typename T>
    string fillRegInitTemplate(llvm::MCRegister Reg, T Imm);
};

/**
 * a template provides all code necessary in addition to the loop code to build an assembly file.
 * usedRegister contains all registers used by the template (like for the loop itself), that should
 * not be used inside the loop body.
 * regInitTemplates hold templates to initialize registers with a given value,
 */
struct Template {
    string prefix, preInit, postInit, preLoop, beginLoop, midLoop, endLoop, postLoop, suffix;
    std::set<string> usedRegisters;
    std::list<RegInitTemplate> regInitTemplates;

    Template(string Prefix, string PreInit, string PostInit, string PreLoop, string BeginLoop,
             string EndLoop, string PostLoop, string Suffix, std::set<string> UsedRegisters,
             std::list<RegInitTemplate> RegInitTemplates);

  private:
    void trimLeadingNewline(string &Str);
};

extern Template X86Template;
extern Template AArch64Template;
extern Template RISCVTemplate;

Template getTemplate(llvm::Triple::ArchType Arch);

} // namespace winic

#endif // TEMPLATES
