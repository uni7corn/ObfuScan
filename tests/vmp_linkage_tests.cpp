#include "vmp_linkage.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

using obfuscan::vmp_linkage::ProviderView;

void expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "[FAIL] " << message << '\n';
        std::exit(1);
    }
}

void test_exact_three_edge_match() {
    const std::vector<ProviderView> providers = {
        {"lib/arm64-v8a/libchoushabi.so", {"vmInterpret", "gVm", "unused"}, true, true}
    };
    const auto result = obfuscan::vmp_linkage::find_protected_provider(
        {"libc.so", "libchoushabi.so"},
        {"malloc", "gVm", "vmInterpret"}, providers);
    expect(result.matched(), "the exact provider/client graph should match");
    expect(result.provider_so == "lib/arm64-v8a/libchoushabi.so",
           "the provider path must remain available as evidence");
    expect(result.shared_symbols == std::vector<std::string>({"gVm", "vmInterpret"}),
           "shared symbols must be deterministic and deduplicated");
}

void test_each_missing_edge_rejects() {
    const ProviderView valid{
        "lib/arm64-v8a/libprovider.so", {"dispatch"}, true, true};
    expect(!obfuscan::vmp_linkage::find_protected_provider(
               {"libother.so"}, {"dispatch"}, {valid}).matched(),
           "symbol overlap without DT_NEEDED must not create a relationship");
    expect(!obfuscan::vmp_linkage::find_protected_provider(
               {"libprovider.so"}, {"other"}, {valid}).matched(),
           "DT_NEEDED without symbol overlap must not create a relationship");

    ProviderView suspicious = valid;
    suspicious.likely_vmp = false;
    expect(!obfuscan::vmp_linkage::find_protected_provider(
               {"libprovider.so"}, {"dispatch"}, {suspicious}).matched(),
           "a merely suspicious provider must not elevate its clients");

    ProviderView low_risk = valid;
    low_risk.high_risk = false;
    expect(!obfuscan::vmp_linkage::find_protected_provider(
               {"libprovider.so"}, {"dispatch"}, {low_risk}).matched(),
           "a non-high-risk provider must not elevate its clients");
}

}  // namespace

int main() {
    test_exact_three_edge_match();
    test_each_missing_edge_rejects();
    std::cout << "[PASS] vmp_linkage_tests\n";
    return 0;
}
