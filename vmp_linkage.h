#pragma once

#include <string>
#include <vector>

namespace obfuscan::vmp_linkage {

struct ProviderView {
    std::string so_name;
    std::vector<std::string> defined_exports;
    bool likely_vmp = false;
    bool high_risk = false;
};

struct LinkEvidence {
    std::string provider_so;
    std::string needed_library;
    std::vector<std::string> shared_symbols;

    bool matched() const {
        return !provider_so.empty() && !needed_library.empty() &&
               !shared_symbols.empty();
    }
};

// Returns a relationship only when all three independent edges are present:
// a high-confidence VMP provider, an exact DT_NEEDED edge, and at least one
// imported symbol actually defined by that provider.
LinkEvidence find_protected_provider(
    const std::vector<std::string>& needed_libraries,
    const std::vector<std::string>& imports,
    const std::vector<ProviderView>& providers);

}  // namespace obfuscan::vmp_linkage
