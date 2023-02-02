#define _CRT_SECURE_NO_WARNINGS

#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <algorithm>
#include <cwctype>

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#define NOMINMAX
#include <windows.h>
#include <shlwapi.h>

#include <stdio.h>
#include <fcntl.h>
#include <io.h>

#define CHECK(x) \
  if (!(x)) LogMessageFatal(__FILE__, __LINE__).stream() << "Check failed: " #x
#define CHECK_EQ(x, y) CHECK((x) == (y))
#ifndef NDEBUG
#define DCHECK(x) CHECK(x)
#define DCHECK_EQ(x, y) CHECK_EQ(x, y)
#else  // NDEBUG
#define DCHECK(condition) \
  while (false) \
    CHECK(condition)
#define DCHECK_EQ(val1, val2) \
  while (false) \
    CHECK_EQ(val1, val2)
#endif

class LogMessage
{
public:
    LogMessage(const char* /*file*/, int /*line*/) {}
    ~LogMessage() { std::cerr << "\n"; }
    std::ostream& stream() { return std::cerr; }
private:
    LogMessage(LogMessage&) = delete;
    void operator=(LogMessage) = delete;
};
class LogMessageFatal : public LogMessage
{
public:
    LogMessageFatal(const char* file, int line)
        : LogMessage(file, line)
    {}
    ~LogMessageFatal()
    {
        std::cerr << "\n";
        std::abort();
    }
private:
    LogMessageFatal(LogMessageFatal&) = delete;
    void operator=(LogMessageFatal) = delete;
};

constexpr wchar_t KeyboardLayoutsRegistryPath[] = L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts";

std::wstring GetKeyboardLayoutDisplayName(_In_ LPCWSTR pwszKLID)
{
    // http://archives.miloush.net/michkap/archive/2006/05/06/591174.html
    typedef HRESULT(WINAPI* SHLoadIndirectStringFunc)(PCWSTR pszSource, PWSTR pszOutBuf, UINT cchOutBuf, void** ppvReserved);
    static SHLoadIndirectStringFunc SHLoadIndirectString = reinterpret_cast<SHLoadIndirectStringFunc>(::GetProcAddress(::LoadLibraryA("shlwapi.dll"), "SHLoadIndirectString"));

    HKEY key;
    CHECK_EQ(::RegOpenKeyW(HKEY_LOCAL_MACHINE, KeyboardLayoutsRegistryPath, &key), ERROR_SUCCESS);

    WCHAR layoutDisplayName[MAX_PATH] = {};
    DWORD layoutDispalyNameSize = static_cast<DWORD>(std::size(layoutDisplayName));

    LSTATUS errorCode = ::RegGetValueW(key, pwszKLID, L"Layout Display Name", RRF_RT_REG_SZ, nullptr, layoutDisplayName, &layoutDispalyNameSize);
    if (errorCode == ERROR_SUCCESS && SHLoadIndirectString)
    {
        // Convert string like "@%SystemRoot%\system32\input.dll,-5000" to localized "US" string
        CHECK_EQ(SHLoadIndirectString(layoutDisplayName, layoutDisplayName, MAX_PATH, nullptr), S_OK);
    }
    else
    {
        // Fallback to unlocalized layout name
        CHECK_EQ(::RegGetValueW(key, pwszKLID, L"Layout Text", RRF_RT_REG_SZ, nullptr, layoutDisplayName, &layoutDispalyNameSize), ERROR_SUCCESS);
    }

    if (errorCode == ERROR_SUCCESS)
    {
        DCHECK(wcslen(layoutDisplayName) != 0);
    }

    CHECK_EQ(::RegCloseKey(key), ERROR_SUCCESS);

    return layoutDisplayName;
}

std::vector<std::wstring> EnumInstalledKeyboardLayouts()
{
    std::vector<std::wstring> layouts;

    HKEY key;
    CHECK_EQ(::RegOpenKeyW(HKEY_LOCAL_MACHINE, KeyboardLayoutsRegistryPath, &key), ERROR_SUCCESS);

    DWORD index = 0;
    WCHAR layoutName[MAX_PATH] = {};
    DWORD layoutNameSize = static_cast<DWORD>(std::size(layoutName));

    while (::RegEnumKeyExW(key, index, layoutName, &layoutNameSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
    {
        layouts.emplace_back(layoutName);
        layoutNameSize = static_cast<DWORD>(std::size(layoutName));
        ++index;
    }

    return layouts;
}

constexpr wchar_t TSFProfilesRegistryPath[] = L"SOFTWARE\\Microsoft\\CTF\\TIP";

// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CTF\TIP\{CLSID}\LanguageProfile\[langid]\{guidProfile}
std::wstring GetTSFProfileRegistryPath(const LCID& langId, const CLSID& clsId, const GUID& profileGuid)
{
    wchar_t* clsIdStr;
    CHECK_EQ(::StringFromCLSID(clsId, &clsIdStr), S_OK);

    wchar_t guidStr[MAX_PATH] = {};
    CHECK(::StringFromGUID2(profileGuid, (LPOLESTR)&guidStr, static_cast<int>(std::size(guidStr))) > 0);

    wchar_t path[MAX_PATH] = {};
    swprintf_s(path, std::size(path), L"%s\\%s\\LanguageProfile\\0x%08x\\%s", TSFProfilesRegistryPath, clsIdStr, langId, guidStr);

    ::CoTaskMemFree(clsIdStr);

    return path;
}

// Format as "<LangID>:{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}"
std::wstring GetTSFProfileString(const LCID& langId, const CLSID& clsId, const GUID& profileGuid)
{
    wchar_t* clsIdStr;
    CHECK_EQ(::StringFromCLSID(clsId, &clsIdStr), S_OK);

    wchar_t guidStr[MAX_PATH] = {};
    CHECK(::StringFromGUID2(profileGuid, (LPOLESTR)&guidStr, static_cast<int>(std::size(guidStr))) > 0);

    wchar_t profileStr[MAX_PATH] = {};
    swprintf_s(profileStr, std::size(profileStr), L"%04x:%s%s", langId, clsIdStr, guidStr);

    ::CoTaskMemFree(clsIdStr);

    return profileStr;
}

std::wstring GetTSFProfileDisplayName(const LCID& langId, const CLSID& clsId, const GUID& profileGuid)
{
    typedef HRESULT(WINAPI* SHLoadIndirectStringFunc)(PCWSTR pszSource, PWSTR pszOutBuf, UINT cchOutBuf, void** ppvReserved);
    static SHLoadIndirectStringFunc SHLoadIndirectString = reinterpret_cast<SHLoadIndirectStringFunc>(::GetProcAddress(::LoadLibraryA("shlwapi.dll"), "SHLoadIndirectString"));

    std::wstring registryPath = GetTSFProfileRegistryPath(langId, clsId, profileGuid);

    HKEY key;
    CHECK_EQ(::RegOpenKeyExW(HKEY_LOCAL_MACHINE, registryPath.c_str(), 0, KEY_READ, &key), ERROR_SUCCESS);

    WCHAR layoutDisplayName[MAX_PATH] = {};
    DWORD layoutDispalyNameSize = static_cast<DWORD>(std::size(layoutDisplayName));

    LSTATUS errorCode = ::RegGetValueW(key, nullptr, L"Display Description", RRF_RT_REG_SZ, nullptr, layoutDisplayName, &layoutDispalyNameSize);
    //if (errorCode == ERROR_SUCCESS && SHLoadIndirectString)
    //{
    //    // Convert string like "@%SystemRoot%\system32\input.dll,-5000" to localized string
    //    CHECK_EQ(SHLoadIndirectString(layoutDisplayName, layoutDisplayName, MAX_PATH, nullptr), S_OK);
    //}
    //else
    {
        // Fallback to unlocalized profile name
        errorCode = ::RegGetValueW(key, nullptr, L"Description", RRF_RT_REG_SZ, nullptr, layoutDisplayName, &layoutDispalyNameSize);
    }

    if (errorCode == ERROR_SUCCESS)
    {
        DCHECK(wcslen(layoutDisplayName) != 0);
    }

    CHECK_EQ(::RegCloseKey(key), ERROR_SUCCESS);

    return layoutDisplayName;
}

std::map<LANGID, std::vector<std::pair<CLSID, GUID>>> EnumInstalledTSFProfiles()
{
    std::map<LANGID, std::vector<std::pair<CLSID, GUID>>> profiles;

    HKEY key;
    CHECK_EQ(::RegOpenKeyExW(HKEY_LOCAL_MACHINE, TSFProfilesRegistryPath, 0, KEY_READ, &key), ERROR_SUCCESS);

    DWORD clsIdIndex = 0;
    WCHAR clsIdStr[MAX_PATH] = {};
    DWORD clsIdStrSize = static_cast<DWORD>(std::size(clsIdStr));

    while (::RegEnumKeyExW(key, clsIdIndex, clsIdStr, &clsIdStrSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
    {
        HKEY clsIdKey;
        CHECK_EQ(::RegOpenKeyExW(key, clsIdStr, 0, KEY_READ, &clsIdKey), ERROR_SUCCESS);

        HKEY profileKey;
        if (::RegOpenKeyExW(clsIdKey, L"LanguageProfile", 0, KEY_READ, &profileKey) == ERROR_SUCCESS)
        {
            DWORD langIdIndex = 0;
            WCHAR langIdStr[MAX_PATH] = {};
            DWORD langIdStrSize = static_cast<DWORD>(std::size(langIdStr));
            while (::RegEnumKeyExW(profileKey, langIdIndex, langIdStr, &langIdStrSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
            {
                HKEY langIdKey;
                CHECK_EQ(::RegOpenKeyW(profileKey, langIdStr, &langIdKey), ERROR_SUCCESS);

                DWORD profileGuidIndex = 0;
                WCHAR profileGuidStr[MAX_PATH] = {};
                DWORD profileGuidStrSize = static_cast<DWORD>(std::size(profileGuidStr));

                while (::RegEnumKeyExW(langIdKey, profileGuidIndex, profileGuidStr, &profileGuidStrSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
                {
                    wchar_t* langIdStrTmp = nullptr;
                    LANGID langId = static_cast<LANGID>(std::wcstoul(langIdStr, &langIdStrTmp, 16));
                    CHECK(langIdStr != langIdStrTmp);

                    CLSID clsId;
                    CHECK_EQ(::CLSIDFromString(clsIdStr, &clsId), NOERROR);

                    GUID guid;
                    CHECK_EQ(::IIDFromString(profileGuidStr, &guid), S_OK);

                    if (_wcsicmp(clsIdStr, L"{36DC059A-160B-497F-A7B8-73E3BAD108D4}") != 0 // Skip Citrix TSF IMEs
                        && langId != 0x0000 && langId != 0xffff) // Skip IMEs profiles with 0 and -1 (all languages) langId
                    {
                        profiles[langId].emplace_back(std::make_pair(clsId, guid));
                    }

                    profileGuidStrSize = static_cast<DWORD>(std::size(profileGuidStr));
                    ++profileGuidIndex;
                }

                CHECK_EQ(::RegCloseKey(langIdKey), ERROR_SUCCESS);

                langIdStrSize = static_cast<DWORD>(std::size(langIdStr));
                ++langIdIndex;
            }

            CHECK_EQ(::RegCloseKey(profileKey), ERROR_SUCCESS);
        }

        CHECK_EQ(::RegCloseKey(clsIdKey), ERROR_SUCCESS);

        clsIdStrSize = static_cast<DWORD>(std::size(clsIdStr));
        ++clsIdIndex;
    }

    CHECK_EQ(::RegCloseKey(key), ERROR_SUCCESS);

    return profiles;
}

std::wstring GetLocaleName(LANGID lang)
{
    wchar_t localeName[MAX_PATH] = {};
    CHECK(::LCIDToLocaleName(lang, localeName, (int)std::size(localeName), 0) > 0);

    return localeName;
}

std::wstring GetLocaleDisplayName(const std::wstring& localeName)
{
    static std::map<std::wstring, std::wstring> cache;
    if (cache.find(localeName) != cache.end())
    {
        return cache[localeName];
    }

    wchar_t languageName[MAX_PATH] = {};
    CHECK(::GetLocaleInfoEx(localeName.c_str(), LOCALE_SENGLISHLANGUAGENAME, languageName, (int)std::size(languageName)) > 0);

    wchar_t countryName[MAX_PATH] = {};
    CHECK(::GetLocaleInfoEx(localeName.c_str(), LOCALE_SENGLISHCOUNTRYNAME, countryName, (int)std::size(countryName)) > 0);

    wchar_t string[MAX_PATH] = {};
    swprintf_s(string, std::size(string), L"%s - %s", languageName, countryName);

    cache[localeName] = string;

    return string;
}

std::wstring GetLanguageDisplayName(LANGID lang)
{
    return GetLocaleDisplayName(GetLocaleName(lang));
}

std::vector<std::wstring> EnumInstalledLocales()
{
    std::vector<std::wstring> locales;

    LOCALE_ENUMPROCEX localeEnumProc = [](LPWSTR localeName, DWORD flags, LPARAM lParam)->BOOL
    {
        if (wcslen(localeName) == 0)
            return TRUE;

        if ((flags & LOCALE_REPLACEMENT) == LOCALE_REPLACEMENT)
            return TRUE;

        if ((flags & LOCALE_ALTERNATE_SORTS) == LOCALE_ALTERNATE_SORTS)
            return TRUE;

        auto locales{ reinterpret_cast<std::vector<std::wstring>*>(lParam) };
        CHECK(locales != nullptr);
        locales->emplace_back(localeName);
        return TRUE;
    };

    CHECK(::EnumSystemLocalesEx(localeEnumProc, LOCALE_WINDOWS, reinterpret_cast<LPARAM>(&locales), nullptr) != 0);

    return locales;
}

std::wstring GetKeyboardsToInstall(const std::wstring& localeName)
{
    wchar_t string[MAX_PATH] = {};
    CHECK(::GetLocaleInfoEx(localeName.c_str(), LOCALE_SKEYBOARDSTOINSTALL, string, (int)std::size(string)) > 0);

    return string;
}

bool endsWith(const std::wstring& s, const std::wstring& suffix)
{
    return s.size() >= suffix.size() &&
        s.substr(s.size() - suffix.size()) == suffix;
}

std::vector<std::wstring> split(const std::wstring& s, const std::wstring& delimiter, const bool removeEmptyEntries = false)
{
    std::vector<std::wstring> tokens;

    for (size_t start = 0, end; start < s.length(); start = end + delimiter.length())
    {
        size_t position = s.find(delimiter, start);
        end = position != std::wstring::npos ? position : s.length();

        std::wstring token = s.substr(start, end - start);
        if (!removeEmptyEntries || !token.empty())
        {
            tokens.push_back(token);
        }
    }

    if (!removeEmptyEntries &&
        (s.empty() || endsWith(s, delimiter)))
    {
        tokens.push_back(L"");
    }

    return tokens;
}

// Get Display name in "<localeName>: <profileDisplayName> (<inputProfile>)" format.
// There are two types of <inputProfile> strings:
// <LangID>:{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
// <LangID>:<KLID>
// 
// Example output:
// sq-AL: Albanian (041c:0000041c)
// am-ET: Amharic Input Method 2 (045e:{7C472071-36A7-4709-88CC-859513E583A9}{9A4E8FC7-76BF-4A63-980D-FADDADF7E987})
std::wstring GetInputProfileDisplayName(const std::wstring& inputProfile, const std::wstring& fallbackLocaleName = L"en-US")
{
    static std::map<std::wstring, std::wstring> cache;
    if (cache.find(inputProfile) != cache.end())
    {
        return cache[inputProfile];
    }

    auto inputProfileTokens = split(inputProfile, L":", true);
    CHECK_EQ(inputProfileTokens.size(), 2);

    wchar_t* langIdStrTmp = nullptr;
    LANGID langId = static_cast<LANGID>(std::wcstoul(inputProfileTokens[0].c_str(), &langIdStrTmp, 16));
    CHECK(inputProfileTokens[0].c_str() != langIdStrTmp);

    std::wstring localeName = (langId == LOCALE_CUSTOM_DEFAULT) ? fallbackLocaleName : GetLocaleName(langId);
    std::wstring profileDisplayName;
    if (inputProfileTokens[1][0] == L'{') // TSF IME
    {
        constexpr size_t guidLen = 38;

        CHECK(inputProfileTokens[1].size() == guidLen * 2);

        CLSID clsId;
        CHECK_EQ(::CLSIDFromString(inputProfileTokens[1].substr(0, guidLen).c_str(), &clsId), NOERROR);

        GUID guid;
        CHECK_EQ(::IIDFromString(inputProfileTokens[1].substr(guidLen).c_str(), &guid), S_OK);

        profileDisplayName = GetTSFProfileDisplayName(langId, clsId, guid);
    }
    else // KLID
    {
        profileDisplayName = GetKeyboardLayoutDisplayName(inputProfileTokens[1].c_str());
    }

    std::wstring inputProfileNormalized = inputProfile;
    // normalize input profile to lower case
    std::transform(inputProfileNormalized.begin(), inputProfileNormalized.end(), inputProfileNormalized.begin(), [](wchar_t c) { return std::towupper(c); });

    wchar_t string[MAX_PATH] = {};
    swprintf_s(string, std::size(string), L"%s: %s (%s)", localeName.c_str(), profileDisplayName.c_str(), inputProfileNormalized.c_str());

    cache[inputProfile] = string;

    return string;
}

std::wstring GetParentLocale(const std::wstring& localeName)
{
    wchar_t string[MAX_PATH] = {};
    CHECK(::GetLocaleInfoEx(localeName.c_str(), LOCALE_SPARENT, string, (int)std::size(string)) > 0);

    return string;
}

int main()
{
    // enable UTF-16 support on console
    (void)_setmode(_fileno(stdout), _O_U16TEXT);

    // Keyboard identifiers
    // https://learn.microsoft.com/windows-hardware/manufacture/desktop/windows-language-pack-default-values#keyboard-identifiers
    {
        std::vector<std::wstring> layouts = EnumInstalledKeyboardLayouts();

        // Sort by Keyboard Layout Name string
        std::sort(layouts.begin(), layouts.end(), [](const auto& a, const auto& b) { return GetKeyboardLayoutDisplayName(a.c_str()) < GetKeyboardLayoutDisplayName(b.c_str());  });

        std::wcout << L"| Keyboard | Keyboard identifier (hexadecimal) |\n";
        std::wcout << L"|-|-|\n";
        for (auto& layout : layouts)
        {
            std::wstring layoutDisplayName = GetKeyboardLayoutDisplayName(layout.c_str());
            std::wcout << L"| " << layoutDisplayName.c_str() << L" | 0x" << layout.c_str() << L" |\n";
        }
    }

    std::wcout << std::endl;

    // Input method editors
    // https://learn.microsoft.com/windows-hardware/manufacture/desktop/windows-language-pack-default-values#input-method-editors
    {
        auto profiles = EnumInstalledTSFProfiles();

        std::vector<LANGID> langs;
        for (const auto& profile : profiles)
        {
            langs.emplace_back(profile.first);
        }

        // Sort by Language Display Name string
        std::sort(langs.begin(), langs.end(), [](const auto& a, const auto& b) { return GetLanguageDisplayName(a) < GetLanguageDisplayName(b);  });

        std::wcout << L"| Language/Region | Input profile (Language and keyboard pair) |\n";
        std::wcout << L"|-|-|\n";
        for (const auto& lang : langs)
        {
            for (const auto& profile_layout : profiles[lang])
            {
                std::wstring localeName = GetLocaleName(lang);
                std::wstring profileString = GetTSFProfileString(lang, profile_layout.first, profile_layout.second);
                std::wstring localeDisplayName = GetLanguageDisplayName(lang);
                std::wstring profileDisplayName = GetInputProfileDisplayName(profileString, localeName);
                std::wcout << L"| " << localeDisplayName << L" | " << profileDisplayName << L" |\n";
            }
        }
    }

    std::wcout << std::endl;

    // Input locales
    // https://learn.microsoft.com/windows-hardware/manufacture/desktop/default-input-locales-for-windows-language-packs#input-locales
    {
        auto locales = EnumInstalledLocales();

        // Sort by Locale Display Name string
        std::sort(locales.begin(), locales.end(), [](const auto& a, const auto& b) { return GetLocaleDisplayName(a) < GetLocaleDisplayName(b);  });

        std::wcout << L"| Language/Region | Primary input profile (language and keyboard pair) | Secondary input profile |\n";
        std::wcout << L"|-|-|-|\n";

        for (const auto& locale : locales)
        {
            std::wstring keyboardsToInstall = GetKeyboardsToInstall(locale);

            // Skip information for locales that have same keyboard layout profile as in corresponding parent locale.
            // 856 -> 426 locales on my system.
            std::wstring parentLocale = GetParentLocale(locale);
            if (!parentLocale.empty() && keyboardsToInstall == GetKeyboardsToInstall(parentLocale))
            {
                continue;
            }

            std::wstring localeDisplayName = GetLocaleDisplayName(locale);
            std::wcout << localeDisplayName << L" | ";

            auto inputProfiles = split(keyboardsToInstall, L";", true);
            for (size_t i = 0; i < inputProfiles.size(); ++i)
            {
                std::wstring profileDisplayName = GetInputProfileDisplayName(inputProfiles[i], locale);

                if (i > 1)
                {
                    std::wcout << L"<br>";
                }

                std::wcout << profileDisplayName;

                if (i == 0)
                {
                    std::wcout << L" | ";
                }
            }

            std::wcout << L" |\n";
        }
    }

    return 0;
}
