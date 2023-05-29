#include <stdint.h>
#include <stdio.h>

#include <fuzzer/FuzzedDataProvider.h>
extern "C"
{
#include "isprefix.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    std::string str2 = provider.ConsumeRandomLengthString();
    const char *cstr = str.c_str();
    const char *cstr2 = str.c_str();
    isprefix(cstr, cstr2);

    return 0;
}
