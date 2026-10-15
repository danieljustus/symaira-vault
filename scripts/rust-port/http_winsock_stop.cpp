// Stop only this CI probe's session and retain SDK-defined final loss counters.
// https://learn.microsoft.com/windows/win32/api/evntrace/nf-evntrace-controltracew
#include <windows.h>
#include <evntrace.h>
#include <cstddef>
#include <cstdio>
#include <cwchar>

static bool probe_session(const wchar_t* name) {
    const wchar_t prefix[] = L"symvault-write-";
    const auto length = std::wcslen(name);
    if (length >= 128 || std::wcsncmp(name, prefix, std::wcslen(prefix)) != 0) {
        return false;
    }
    const wchar_t* part = name + std::wcslen(prefix);
    for (int group = 0; group < 2; ++group) {
        const wchar_t* start = part;
        while (*part >= L'0' && *part <= L'9') ++part;
        if (part == start) return false;
        if (group == 0 && *part++ != L'-') return false;
    }
    return *part == L'\0';
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 2 || !probe_session(argv[1])) {
        std::fputs("Expected the exact symvault-write-<run>-<attempt> session\n", stderr);
        return 2;
    }
    struct TraceProperties {
        EVENT_TRACE_PROPERTIES properties;
        wchar_t logger_name[1025];
        wchar_t log_file_name[1025];
    } data{};
    data.properties.Wnode.BufferSize = static_cast<ULONG>(sizeof(data));
    data.properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    data.properties.LoggerNameOffset = static_cast<ULONG>(offsetof(TraceProperties, logger_name));
    data.properties.LogFileNameOffset = static_cast<ULONG>(offsetof(TraceProperties, log_file_name));
    const ULONG status = ControlTraceW(0, argv[1], &data.properties, EVENT_TRACE_CONTROL_STOP);
    if (status != ERROR_SUCCESS) {
        // Never publish the raw trace, paths, addresses, or a fabricated zero.
        std::fprintf(stderr, "ControlTraceW stop failed: %lu\n", status);
        return 1;
    }
    if (std::wcscmp(data.logger_name, argv[1]) != 0 || data.log_file_name[0] == L'\0') {
        std::fputs("Stopped-session identity or file-backed trace is missing\n", stderr);
        return 1;
    }
    std::printf("{\"source\":\"ControlTraceW(EVENT_TRACE_CONTROL_STOP)\","
                "\"session\":\"%ls\",\"session_stopped\":true,"
                "\"events_lost\":%lu,\"log_buffers_lost\":%lu,"
                "\"real_time_buffers_lost\":%lu,\"buffers_written\":%lu}\n",
                argv[1], data.properties.EventsLost, data.properties.LogBuffersLost,
                data.properties.RealTimeBuffersLost, data.properties.BuffersWritten);
    return std::ferror(stdout) ? 1 : 0;
}
