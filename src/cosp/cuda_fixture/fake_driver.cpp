// Linker-only CUDA Driver API fixture. Never delegates to an actual loader.
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>
#include <dlfcn.h>

namespace {
struct Uuid { char bytes[16]; };
using Ptr = unsigned long long;
constexpr Ptr token = 1;
int handle, context, module, function;
std::array<float, 16> data{};
constexpr unsigned char gpu_a[] = {0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa};
constexpr unsigned char gpu_b[] = {0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb};
bool mode(std::string_view name) { const char* value = std::getenv("CUDA_FIXTURE_CASE"); return value && name == value; }
void log(const char* msg) { std::fprintf(stderr, "%s\n", msg); }
int cuInit(unsigned flags) { log("init"); return flags || mode("init-failure"); }
int cuDeviceGetCount(int* n) { log("count"); *n = mode("a-only") || mode("b-only") ? 1 : 2; return 0; }
int cuDeviceGet(int* dev, int ordinal) { *dev = ordinal; return 0; }
int cuDeviceGetUuid_v2(Uuid* uuid, int ordinal) {
    bool is_a = mode("a-only") || (!mode("b-only") && ordinal == (mode("reversed") ? 0 : 1));
    std::memcpy(uuid->bytes, is_a ? gpu_a : gpu_b, sizeof(uuid->bytes)); return 0;
}
int cuCtxCreate_v2(void** ctx, unsigned flags, int dev) {
    std::fprintf(stderr, "context:%d\n", dev);
    if (flags || mode("context-failure")) return 1;
    *ctx = &context; return 0;
}
int cuCtxSetCurrent(void* ctx) { return ctx != &context; }
int cuCtxDestroy_v2(void* ctx) { log("destroy"); return ctx != &context; }
int cuMemAlloc_v2(Ptr* ptr, std::size_t n) {
    std::fprintf(stderr, "allocate:%zu\n", n);
    if (n != sizeof(data)) return 1;
    *ptr = token; return 0;
}
int cuMemFree_v2(Ptr ptr) { log("free"); return ptr != token; }
int cuMemcpyHtoD_v2(Ptr ptr, const void* from, std::size_t n) {
    log("upload"); if (ptr != token || n != sizeof(data)) return 1;
    std::memcpy(data.data(), from, n); return 0;
}
int cuMemcpyDtoH_v2(void* to, Ptr ptr, std::size_t n) {
    log("download"); if (ptr != token || n != sizeof(data)) return 1;
    std::memcpy(to, data.data(), n); return 0;
}
int cuModuleLoadData(void** mod, const void* ptx) {
    log("module"); if (!std::strstr(static_cast<const char*>(ptx), ".entry add_one(")) return 1;
    *mod = &module; return 0;
}
int cuModuleGetFunction(void** fn, void* mod, const char* name) {
    std::fprintf(stderr, "entry:%s\n", name);
    if (mod != &module || std::string_view(name) != "add_one") return 1;
    *fn = &function; return 0;
}
int cuModuleUnload(void* mod) { log("unload"); return mod != &module; }
int cuLaunchKernel(void* fn, unsigned gx, unsigned gy, unsigned gz, unsigned bx, unsigned by,
                   unsigned bz, unsigned shared, void* stream, void** args, void** extra) {
    std::fprintf(stderr, "launch:%u\n", bx);
    if (mode("launch-failure") || fn != &function || gx != 1 || gy != 1 || gz != 1 ||
        bx != data.size() || by != 1 || bz != 1 || shared || stream || !args || extra ||
        *static_cast<Ptr*>(args[0]) != token || *static_cast<unsigned*>(args[1]) != data.size()) return 1;
    // Synthetic readback only: proves host-path branching, not CUDA execution.
    for (float& value : data) value += 1.0f;
    if (mode("corrupt-output")) data.back() = -1;
    return 0;
}
int cuCtxSynchronize() { log("sync"); return 0; }
}

extern "C" void* __wrap_dlopen(const char* lib, int flags) {
    log("loader:fixture");
    return std::string_view(lib) == "libcuda.so.1" && flags == (RTLD_NOW | RTLD_LOCAL) &&
        !mode("no-driver") ? &handle : nullptr;
}
extern "C" void* __wrap_dlsym(void* lib, const char* symbol) {
    if (lib != &handle) return nullptr;
    std::string_view name(symbol);
#define SYMBOL(s) if (name == #s) return reinterpret_cast<void*>(&s)
    SYMBOL(cuInit); SYMBOL(cuDeviceGetCount); SYMBOL(cuDeviceGet); SYMBOL(cuDeviceGetUuid_v2);
    SYMBOL(cuCtxCreate_v2); SYMBOL(cuCtxSetCurrent); SYMBOL(cuCtxDestroy_v2);
    SYMBOL(cuMemAlloc_v2); SYMBOL(cuMemFree_v2); SYMBOL(cuMemcpyHtoD_v2); SYMBOL(cuMemcpyDtoH_v2);
    SYMBOL(cuModuleLoadData); SYMBOL(cuModuleGetFunction); SYMBOL(cuModuleUnload);
    SYMBOL(cuLaunchKernel); SYMBOL(cuCtxSynchronize);
#undef SYMBOL
    return nullptr;
}
extern "C" int __wrap_dlclose(void* lib) {
    log("close");
    if (mode("close-failure")) {
        log("injected:close-failure");
        return 1;
    }
    return lib != &handle;
}
