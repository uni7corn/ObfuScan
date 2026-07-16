#include "vmp_linkage.h"

#include <algorithm>
#include <unordered_set>

namespace obfuscan::vmp_linkage {
namespace {

std::string basename(const std::string& path) {
    const size_t pos = path.find_last_of("/\\");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

}  // namespace

LinkEvidence find_protected_provider(
        const std::vector<std::string>& needed_libraries,
        const std::vector<std::string>& imports,
        const std::vector<ProviderView>& providers) {
    LinkEvidence best;
    if (needed_libraries.empty() || imports.empty()) return best;

    const std::unordered_set<std::string> imported(imports.begin(), imports.end());
    for (const auto& needed : needed_libraries) {
        if (needed.empty()) continue;
        for (const auto& provider : providers) {
            if (!provider.likely_vmp || !provider.high_risk ||
                basename(provider.so_name) != needed) {
                continue;
            }

            std::vector<std::string> shared;
            std::unordered_set<std::string> seen;
            for (const auto& symbol : provider.defined_exports) {
                if (!symbol.empty() && imported.count(symbol) != 0 &&
                    seen.insert(symbol).second) {
                    shared.push_back(symbol);
                }
            }
            std::sort(shared.begin(), shared.end());
            if (shared.size() > best.shared_symbols.size()) {
                best.provider_so = provider.so_name;
                best.needed_library = needed;
                best.shared_symbols = std::move(shared);
            }
        }
    }
    return best;
}

}  // namespace obfuscan::vmp_linkage
