#include <Windows.h>

#include "global/global.h"
#include "memory/zywrap/zywrap.h"
#include "engine/dumper/dumper.h"
#include "memory/scanner/scanner.h"
#include "engine/communications/communications.h"
#include "third-party/minhook/include/MinHook.h"

void entry()
{
    auto func = ([]() -> void // Run before socket connects
    {
        auto start = std::chrono::high_resolution_clock::now();

        scanner::init();

        zywrap zywrap{};

        engine::dumper::dumper_t dumper(zywrap);

        dumper.dump();

        std::stringstream output_stream;
        output_stream << dumper.output().str() << "\n";

#if MULTI_THREADED
        while (comm_socket == nullptr)
        {
            volatile int a = 0;
        } // Wait for socket to connect
#endif

        auto stop = std::chrono::high_resolution_clock::now();

        ipc_write("Welcome to UWP Dumper!\n");
        output_stream << "\nTook " << std::chrono::duration_cast<std::chrono::milliseconds>(stop - start) << "!\n";
        ipc_write(output_stream.str().c_str());
    });

#if MULTI_THREADED
    std::thread(func).detach();

    if (!engine::communications::start()) // Connect to socket
        ipc_write("Failed to setup socket!\n");
#else
    if (!engine::communications::start()) // Connect to socket
        ipc_write("Failed to setup socket!\n");

    func();
#endif
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            std::thread(entry).detach();
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}