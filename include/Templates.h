#ifndef TEMPLATES_H
#define TEMPLATES_H

#include "llvm/TargetParser/Triple.h"
#include <set>
#include <string>
#include <utility>
#include <vector>

using std::string;

/**
 * a template provides all code necessary in addition to the loop code to build an assembly file.
 * usedRegister contains all registers used by the template (like for the loop itself). Those should
 * not be used by the benchmark generators.
 * regInitTemplates hold templates to initialize registers with a given value,
 */
struct Template {
    string prefix, preInit, postInit, preLoop, beginLoop, midLoop, endLoop, postLoop, suffix;
    std::vector<std::pair<string, string>> regInitTemplates;
    std::set<string> usedRegisters;

    Template(string Prefix, string PreInit, string PostInit, string PreLoop, string BeginLoop,
             string EndLoop, string PostLoop, string Suffix,
             std::vector<std::pair<string, string>> RegInitCode, std::set<string> UsedRegisters);

  private:
    void trimLeadingNewline(string &Str);
};

extern Template X86Template;
extern Template AArch64Template;
extern Template RISCVTemplate;

Template getTemplate(llvm::Triple::ArchType Arch);

#endif // TEMPLATES
