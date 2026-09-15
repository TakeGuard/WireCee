#ifndef CEF_INCLUDE_CEF_VERSION_H_
#define CEF_INCLUDE_CEF_VERSION_H_

#define CEF_VERSION "107.0.1+g318ab17+chromium-107.0.5304.18"
#define CEF_VERSION_MAJOR 107
#define CEF_VERSION_MINOR 0
#define CEF_VERSION_PATCH 1
#define CEF_COMMIT_NUMBER 2670
#define CEF_COMMIT_HASH "318ab1716eebf5bd8fa5b45f0f72b3f7c59dd459"
#define COPYRIGHT_YEAR 2022

#define CHROME_VERSION_MAJOR 107
#define CHROME_VERSION_MINOR 0
#define CHROME_VERSION_BUILD 5304
#define CHROME_VERSION_PATCH 18

#define DO_MAKE_STRING(p) #p
#define MAKE_STRING(p) DO_MAKE_STRING(p)

#ifndef APSTUDIO_HIDDEN_SYMBOLS

#include "include/internal/cef_export.h"

#ifdef __cplusplus
extern "C" {
#endif

// Returns CEF version information for the libcef library. The |entry|
// parameter describes which version component will be returned:
// 0 - CEF_VERSION_MAJOR
// 1 - CEF_VERSION_MINOR
// 2 - CEF_VERSION_PATCH
// 3 - CEF_COMMIT_NUMBER
// 4 - CHROME_VERSION_MAJOR
// 5 - CHROME_VERSION_MINOR
// 6 - CHROME_VERSION_BUILD
// 7 - CHROME_VERSION_PATCH
///
CEF_EXPORT int cef_version_info(int entry);

#ifdef __cplusplus
}
#endif

#endif  // APSTUDIO_HIDDEN_SYMBOLS

#endif  // CEF_INCLUDE_CEF_VERSION_H_
