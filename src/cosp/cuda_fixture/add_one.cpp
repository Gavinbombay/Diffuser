// Private test helper; loader symbols must be provided by the link-time fake.
// Derived from the verified retained CUDA canary.
// Bounded NVIDIA Driver API vector operation. No CUDA toolkit headers or runtime are required.
// Function signatures and ABI names follow NVIDIA's primary CUDA Driver API reference:
// https://docs.nvidia.com/cuda/cuda-driver-api/cuda_8h_source.html
// https://docs.nvidia.com/cuda/cuda-driver-api/cuda_driver_api/group__CUDA__DEVICE.html
// https://docs.nvidia.com/cuda/cuda-driver-api/cuda_driver_api/group__CUDA__CTX.html
// https://docs.nvidia.com/cuda/cuda-driver-api/cuda_driver_api/group__CUDA__MEM.html
// https://docs.nvidia.com/cuda/cuda-driver-api/cuda_driver_api/group__CUDA__EXEC.html
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

extern "C" void* __wrap_dlopen(const char*, int);
extern "C" void* __wrap_dlsym(void*, const char*);
extern "C" int __wrap_dlclose(void*);

using CUresult=int; using CUdevice=int; using CUcontext=void*; using CUmodule=void*; using CUfunction=void*; using CUdeviceptr=unsigned long long;
struct CUuuid { char bytes[16]; };
constexpr CUresult CUDA_SUCCESS=0;
constexpr std::size_t kElements=16;
constexpr std::size_t kMaxBytes=4096;

class Driver {
 public:
  Driver(){ handle_=__wrap_dlopen("libcuda.so.1",RTLD_NOW|RTLD_LOCAL); if(!handle_) return;
#define LOAD(name, type) name=reinterpret_cast<type>(__wrap_dlsym(handle_,#name)); if(!name) return
    LOAD(cuInit,CUresult(*)(unsigned int)); LOAD(cuDeviceGetCount,CUresult(*)(int*)); LOAD(cuDeviceGet,CUresult(*)(CUdevice*,int));
    cuDeviceGetUuid=reinterpret_cast<CUresult(*)(CUuuid*,CUdevice)>(__wrap_dlsym(handle_,"cuDeviceGetUuid_v2"));
    if(!cuDeviceGetUuid) cuDeviceGetUuid=reinterpret_cast<CUresult(*)(CUuuid*,CUdevice)>(__wrap_dlsym(handle_,"cuDeviceGetUuid"));
    if(!cuDeviceGetUuid)return;
    LOAD(cuCtxCreate_v2,CUresult(*)(CUcontext*,unsigned int,CUdevice)); LOAD(cuCtxSetCurrent,CUresult(*)(CUcontext)); LOAD(cuCtxDestroy_v2,CUresult(*)(CUcontext));
    LOAD(cuMemAlloc_v2,CUresult(*)(CUdeviceptr*,std::size_t)); LOAD(cuMemFree_v2,CUresult(*)(CUdeviceptr));
    LOAD(cuMemcpyHtoD_v2,CUresult(*)(CUdeviceptr,const void*,std::size_t)); LOAD(cuMemcpyDtoH_v2,CUresult(*)(void*,CUdeviceptr,std::size_t));
    LOAD(cuModuleLoadData,CUresult(*)(CUmodule*,const void*)); LOAD(cuModuleGetFunction,CUresult(*)(CUfunction*,CUmodule,const char*)); LOAD(cuModuleUnload,CUresult(*)(CUmodule));
    LOAD(cuLaunchKernel,CUresult(*)(CUfunction,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,void*,void**,void**)); LOAD(cuCtxSynchronize,CUresult(*)());
#undef LOAD
    ready=true;
  }
  Driver(const Driver&) = delete;
  Driver& operator=(const Driver&) = delete;
  ~Driver() { close(); }
  int close() noexcept {
    if (!handle_) return 0;
    void* handle = handle_;
    handle_ = nullptr;
    ready = false;
    return __wrap_dlclose(handle);
  }
  bool ready=false;
  CUresult(*cuInit)(unsigned int)=nullptr;CUresult(*cuDeviceGetCount)(int*)=nullptr;CUresult(*cuDeviceGet)(CUdevice*,int)=nullptr;CUresult(*cuDeviceGetUuid)(CUuuid*,CUdevice)=nullptr;
  CUresult(*cuCtxCreate_v2)(CUcontext*,unsigned int,CUdevice)=nullptr;CUresult(*cuCtxSetCurrent)(CUcontext)=nullptr;CUresult(*cuCtxDestroy_v2)(CUcontext)=nullptr;
  CUresult(*cuMemAlloc_v2)(CUdeviceptr*,std::size_t)=nullptr;CUresult(*cuMemFree_v2)(CUdeviceptr)=nullptr;CUresult(*cuMemcpyHtoD_v2)(CUdeviceptr,const void*,std::size_t)=nullptr;CUresult(*cuMemcpyDtoH_v2)(void*,CUdeviceptr,std::size_t)=nullptr;
  CUresult(*cuModuleLoadData)(CUmodule*,const void*)=nullptr;CUresult(*cuModuleGetFunction)(CUfunction*,CUmodule,const char*)=nullptr;CUresult(*cuModuleUnload)(CUmodule)=nullptr;
  CUresult(*cuLaunchKernel)(CUfunction,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,void*,void**,void**)=nullptr;CUresult(*cuCtxSynchronize)()=nullptr;
 private:void* handle_=nullptr;
};
struct Cleanup {
    explicit Cleanup(Driver& driver) : d(driver) {}
    Cleanup(const Cleanup&) = delete;
    Cleanup& operator=(const Cleanup&) = delete;
    Driver& d;
    CUcontext ctx=nullptr;
    CUmodule mod=nullptr;
    CUdeviceptr mem=0;
    bool finish() noexcept {
        bool ok = true;
        const auto check = [&ok](const char* api, int rc) {
            if (rc != CUDA_SUCCESS) {
                ok = false;
                std::fprintf(stderr, "CUDA cleanup failed: %s rc=%d\n", api, rc);
            }
        };
        // Attempt every owned resource once, regardless of previous failures.
        if (ctx) {
            check("cuCtxSetCurrent", d.cuCtxSetCurrent(ctx));
            check("cuCtxSynchronize", d.cuCtxSynchronize());
        }
        if (mem) check("cuMemFree_v2", d.cuMemFree_v2(mem));
        if (mod) check("cuModuleUnload", d.cuModuleUnload(mod));
        if (ctx) check("cuCtxDestroy_v2", d.cuCtxDestroy_v2(ctx));
        ctx=nullptr; mod=nullptr; mem=0;
        check("dlclose", d.close());
        return ok;
    }
    ~Cleanup(){finish();}
};
static std::string uuid_text(const CUuuid& u){std::ostringstream o;o<<"GPU-"<<std::hex<<std::setfill('0');for(int i=0;i<16;i++){if(i==4||i==6||i==8||i==10)o<<'-';o<<std::setw(2)<<(static_cast<unsigned int>(static_cast<unsigned char>(u.bytes[i])));}return o.str();}
static int select(Driver& d,const std::string& wanted) {
    int count=0, selected=-1;
    if(d.cuDeviceGetCount(&count)!=CUDA_SUCCESS || count<=0 || count>64) return -1;
    for(int i=0;i<count;++i){
        CUdevice candidate=0; CUuuid id{};
        if(d.cuDeviceGet(&candidate,i)!=CUDA_SUCCESS || d.cuDeviceGetUuid(&id,candidate)!=CUDA_SUCCESS) return -1;
        if(wanted==uuid_text(id)) {
            if(selected>=0) return -1;
            selected=candidate;
        }
    }
    return selected;
}
// The fake uses only inherited pipes and memory; no device opens, socket,
// process creation or later exec after the dynamic linker has finished.
static bool restrict_fixture() {
#if defined(__linux__) && defined(__x86_64__)
#define ALLOW(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_##n, 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        ALLOW(read), ALLOW(write), ALLOW(close), ALLOW(fstat),
        ALLOW(brk), ALLOW(mmap), ALLOW(munmap), ALLOW(futex),
        ALLOW(exit), ALLOW(exit_group), ALLOW(rt_sigreturn),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
#undef ALLOW
    sock_fprog program{static_cast<unsigned short>(sizeof(code)/sizeof(code[0])), code};
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)==0;
#else
    return false;
#endif
}
int main(int argc,char**argv){
 if(argc!=2) return 2;
 // Initialize libc's stdout buffering before the filter (some libc versions
 // use newfstatat to inspect the pipe when first buffering it).
 if(setvbuf(stdout,nullptr,_IONBF,0)!=0 || !restrict_fixture()) return 2;
 const std::string selected=argv[1];
 Driver d;
 if(!d.ready || d.cuInit(0)!=CUDA_SUCCESS || select(d,selected)<0) return 3;
 std::cout << 'R' << std::flush;
 char go=0, extra=0;
 if(read(STDIN_FILENO,&go,1)!=1 || go!='G' || read(STDIN_FILENO,&extra,1)!=0) return 2;
 const int dev=select(d,selected);
 if(dev<0) return 3;
 CUuuid uuid{};
 if(d.cuDeviceGetUuid(&uuid,dev)!=CUDA_SUCCESS || uuid_text(uuid)!=selected) return 3;
 // Failed acquisitions do not transfer ownership of their out-parameters.
 Cleanup cleanup{d};
 CUcontext ctx=nullptr;
 if(d.cuCtxCreate_v2(&ctx,0,dev)!=CUDA_SUCCESS){std::cout<<"{\"status\":\"CUDA_UNAVAILABLE\",\"reason\":\"selected CUDA context could not be created\"}\n";return 3;}
 cleanup.ctx=ctx;
 if(d.cuCtxSetCurrent(cleanup.ctx)!=CUDA_SUCCESS){std::cout<<"{\"status\":\"CUDA_UNAVAILABLE\",\"reason\":\"selected CUDA context could not be made current\"}\n";return 3;}
 std::array<float,kElements> values{};for(std::size_t i=0;i<values.size();++i)values[i]=static_cast<float>(i);
 constexpr std::size_t bytes=kElements*sizeof(float);
 static_assert(bytes<=kMaxBytes);
 CUdeviceptr mem=0;
 if(d.cuMemAlloc_v2(&mem,bytes)!=CUDA_SUCCESS){std::cout<<"{\"status\":\"CUDA_UNAVAILABLE\",\"reason\":\"bounded device allocation failed\"}\n";return 3;}
 cleanup.mem=mem;
 if(d.cuMemcpyHtoD_v2(mem,values.data(),bytes)!=CUDA_SUCCESS){std::cout<<"{\"status\":\"CUDA_UNAVAILABLE\",\"reason\":\"bounded device upload failed\"}\n";return 3;}
 static constexpr char ptx[]=R"PTX(.version 6.0
.target sm_52
.address_size 64
.visible .entry add_one(.param .u64 ptr, .param .u32 n) {
 .reg .pred %p; .reg .b32 %r<3>; .reg .b64 %rd<5>; .reg .f32 %f;
 ld.param.u64 %rd1, [ptr]; ld.param.u32 %r1, [n]; mov.u32 %r2, %tid.x; setp.ge.u32 %p, %r2, %r1; @%p bra DONE;
 mul.wide.u32 %rd2, %r2, 4; add.s64 %rd3, %rd1, %rd2; ld.global.f32 %f, [%rd3]; add.f32 %f, %f, 0f3f800000; st.global.f32 [%rd3], %f;
 DONE: ret;
})PTX";
 CUmodule mod=nullptr;
 if(d.cuModuleLoadData(&mod,ptx)!=CUDA_SUCCESS){std::cout<<"{\"status\":\"CUDA_UNAVAILABLE\",\"reason\":\"embedded PTX module load failed\"}\n";return 3;}
 cleanup.mod=mod;
 CUfunction fn=nullptr;if(d.cuModuleGetFunction(&fn,cleanup.mod,"add_one")!=CUDA_SUCCESS){std::cout<<"{\"status\":\"CUDA_UNAVAILABLE\",\"reason\":\"vector kernel lookup failed\"}\n";return 3;}
 unsigned int n=static_cast<unsigned int>(values.size());void* args[]={&cleanup.mem,&n};if(d.cuLaunchKernel(fn,1,1,1,n,1,1,0,nullptr,args,nullptr)!=CUDA_SUCCESS||d.cuCtxSynchronize()!=CUDA_SUCCESS){std::cout<<"{\"status\":\"CUDA_UNAVAILABLE\",\"reason\":\"CUDA kernel launch or synchronization failed\"}\n";return 3;}
 std::array<float,kElements> result{};if(d.cuMemcpyDtoH_v2(result.data(),cleanup.mem,result.size()*sizeof(float))!=CUDA_SUCCESS){std::cout<<"{\"status\":\"CUDA_UNAVAILABLE\",\"reason\":\"CUDA result transfer failed\"}\n";return 3;}
 for(std::size_t i=0;i<result.size();++i)if(result[i]!=static_cast<float>(i+1)){std::cerr<<"CUDA output verification failed\n";return 4;}
 // The checked-cleanup contract uses 6 for a cleanup-only failure. The
 // single-use Rust binding treats any nonzero armed exit as uncertain.
 // Never put a readback frame on stdout unless cleanup also succeeded.
 if(!cleanup.finish()) return 6;
 std::cout << "{\"device_uuid\":\"" << uuid_text(uuid) << "\",\"workload\":\"add_one\",\"values\":[";
 for(std::size_t i=0;i<result.size();++i) std::cout << (i ? "," : "") << static_cast<unsigned>(result[i]);
 std::cout << "]}\n";
 return std::cout ? 0 : 5;
}
