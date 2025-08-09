#ifndef TEMPLATES_H
#define TEMPLATES_H

#include "llvm/TargetParser/Triple.h"
#include <set>
#include <string>

using std::string;

namespace winic {

/**
 * a template provides all code necessary in addition to the loop code to build an assembly file.
 * usedRegister contains all registers used by the template (like for the loop itself). Those should
 * not be used by the benchmark generators.
 * regInitTemplates hold templates to initialize registers with a given value,
 */
struct Template {
    string prefix, preInit, postInit, preLoop, beginLoop, midLoop, endLoop, postLoop, suffix;
    std::set<string> usedRegisters;

    Template(string Prefix, string PreInit, string PostInit, string PreLoop, string BeginLoop,
             string EndLoop, string PostLoop, string Suffix, std::set<string> UsedRegisters);

  private:
    void trimLeadingNewline(string &Str);
};

extern Template X86Template;
extern Template AArch64Template;
extern Template RISCVTemplate;

Template getTemplate(llvm::Triple::ArchType Arch);

} // namespace winic

#endif // TEMPLATES
