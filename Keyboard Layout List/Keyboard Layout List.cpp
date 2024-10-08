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

namespace utils
{
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

    void towlower(std::wstring& string)
    {
        for (wchar_t& ch : string)
        {
            ch = std::towlower(ch);
        }
    }

    void towupper(std::wstring& string)
    {
        for (wchar_t& ch : string)
        {
            ch = std::towupper(ch);
        }
    }

    size_t GetGuidStringLength()
    {
        wchar_t guidStr[MAX_PATH] = {};
        CHECK(::StringFromGUID2(GUID_NULL, (LPOLESTR)&guidStr, static_cast<int>(std::size(guidStr))) > 0);

        return wcslen(guidStr);
    }

    size_t GetClsIdStringLength()
    {
        wchar_t* clsIdStr;
        CHECK_EQ(::StringFromCLSID(CLSID_NULL, &clsIdStr), S_OK);

        size_t len = wcslen(clsIdStr);

        ::CoTaskMemFree(clsIdStr);

        return len;
    }

    // length of {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} string
    size_t GetTSFProfileStringLength()
    {
        static size_t len = GetGuidStringLength() + GetClsIdStringLength();
        return len;
    }
}

constexpr wchar_t KeyboardLayoutsRegistryPath[] = L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts";

std::wstring GetKeyboardLayoutDisplayName(_In_ LPCWSTR pwszKLID)
{
    // http://archives.miloush.net/michkap/archive/2006/05/06/591174.html
    typedef HRESULT(WINAPI* SHLoadIndirectStringFunc)(PCWSTR pszSource, PWSTR pszOutBuf, UINT cchOutBuf, void** ppvReserved);
    static SHLoadIndirectStringFunc SHLoadIndirectString = reinterpret_cast<SHLoadIndirectStringFunc>(::GetProcAddress(::LoadLibraryA("shlwapi.dll"), "SHLoadIndirectString"));

    HKEY key;
    CHECK_EQ(::RegOpenKeyExW(HKEY_LOCAL_MACHINE, KeyboardLayoutsRegistryPath, 0, KEY_READ, &key), ERROR_SUCCESS);

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

std::wstring GetKeyboardLayoutLink(_In_ LPCWSTR pwszKLID)
{
    static std::map<std::wstring, std::wstring> cache;
    if (cache.find(pwszKLID) != cache.end())
    {
        return cache[pwszKLID];
    }

    {
        wchar_t* langIdStrTmp = nullptr;
        LCID klid = static_cast<LCID>(std::wcstoul(pwszKLID, &langIdStrTmp, 16));
        CHECK(pwszKLID != langIdStrTmp);

        // Custom layout
        if ((klid & 0xa0000000) == 0xa0000000)
        {
            return {};
        }
    }

    struct KnownKLIDs
    {
        LPCWSTR klid;
        LPCWSTR name;
    } known[] =
    {
        { L"00000401", L"kbda1"},
        { L"00000402", L"kbdbu"},
        { L"00000404", L"kbdus_4"},
        { L"00000405", L"kbdcz"},
        { L"00000406", L"kbdda"},
        { L"00000407", L"kbdgr"},
        { L"00000408", L"kbdhe"},
        { L"00000409", L"kbdus_7"},
        { L"0000040A", L"kbdsp"},
        { L"0000040B", L"kbdfi"},
        { L"0000040C", L"kbdfr"},
        { L"0000040E", L"kbdhu"},
        { L"0000040F", L"kbdic"},
        { L"0000040D", L"kbdheb"},
        { L"00000410", L"kbdit"},
        { L"00000411", L"kbdjpn"},
        { L"00000412", L"kbdkor"},
        { L"00000413", L"kbdne"},
        { L"00000414", L"kbdno"},
        { L"00000415", L"kbdpl1"},
        { L"00000416", L"kbdbr_1"},
        { L"00000418", L"kbdro"},
        { L"00000419", L"kbdru"},
        { L"0000041A", L"kbdcr_2"},
        { L"0000041B", L"kbdsl"},
        { L"0000041C", L"kbdal"},
        { L"0000041D", L"kbdsw"},
        { L"0000041E", L"kbdth0"},
        { L"0000041F", L"kbdtuq"},
        { L"00000420", L"kbdurdu"},
        { L"00000422", L"kbdur"},
        { L"00000423", L"kbdblr"},
        { L"00000424", L"kbdcr_1"},
        { L"00000425", L"kbdest"},
        { L"00000426", L"kbdlv"},
        { L"00000427", L"kbdlt"},
        { L"00000428", L"kbdtajik"},
        { L"00000429", L"kbdfa"},
        { L"0000042A", L"kbdvntc"},
        { L"0000042C", L"kbdazel"},
        { L"0000042B", L"kbdarme"},
        { L"0000042E", L"kbdsorst"},
        { L"0000042F", L"kbdmac"},
        { L"00000432", L"kbdnso_2"},
        { L"00000437", L"kbdgeo"},
        { L"00000438", L"kbdfo"},
        { L"00000439", L"kbdindev"},
        { L"0000043A", L"kbdmlt47"},
        { L"0000043B", L"kbdno1"},
        { L"0000043F", L"kbdkaz"},
        { L"00000440", L"kbdkyr"},
        { L"00000442", L"kbdturme"},
        { L"00000444", L"kbdtat"},
        { L"00000445", L"kbdinben"},
        { L"00000446", L"kbdinpun"},
        { L"00000447", L"kbdinguj"},
        { L"00000448", L"kbdinori"},
        { L"00000449", L"kbdintam"},
        { L"0000044A", L"kbdintel"},
        { L"0000044B", L"kbdinkan"},
        { L"0000044C", L"kbdinmal"},
        { L"0000044D", L"kbdinasa"},
        { L"0000044E", L"kbdinmar"},
        { L"00000450", L"kbdmon"},
        { L"00000451", L"kbdtiprc"},
        { L"00000452", L"kbdukx"},
        { L"00000453", L"kbdkhmr"},
        { L"00000454", L"kbdlao"},
        { L"0000045A", L"kbdsyr1"},
        { L"0000045B", L"kbdsn1"},
        { L"0000045C", L"kbdcher"},
        { L"00000461", L"kbdnepr"},
        { L"00000463", L"kbdpash"},
        { L"00000465", L"kbddiv1"},
        { L"00000468", L"kbdhau"},
        { L"0000046A", L"kbdyba"},
        { L"0000046C", L"kbdnso_1"},
        { L"0000046D", L"kbdbash"},
        { L"0000046E", L"kbdsf_1"},
        { L"0000046F", L"kbdgrlnd"},
        { L"00000470", L"kbdibo"},
        { L"00000474", L"kbdgn"},
        { L"00000475", L"kbdhaw"},
        { L"00000480", L"kbdughr"},
        { L"00000481", L"kbdmaori"},
        { L"00000485", L"kbdyak"},
        { L"00000488", L"kbdwol"},
        { L"00000492", L"kbdkurd"},
        { L"00000804", L"kbdus_2"},
        { L"00000807", L"kbdsg"},
        { L"00000809", L"kbduk"},
        { L"0000080A", L"kbdla"},
        { L"0000080C", L"kbdbe_2"},
        { L"00000813", L"kbdbe_1"},
        { L"00000816", L"kbdpo"},
        { L"0000081A", L"kbdycl"},
        { L"0000082C", L"kbdaze"},
        { L"0000083B", L"kbdfi1_2"},
        { L"00000843", L"kbduzb"},
        { L"00000850", L"kbdmonmo"},
        { L"0000085D", L"kbdiulat"},
        { L"0000085F", L"kbdtzm"},
        { L"00000C1A", L"kbdycc"},
        { L"00000C51", L"kbddzo"},
        { L"00000C04", L"kbdus_5"},
        { L"00000C0C", L"kbdfc"},
        { L"00001004", L"kbdus_3"},
        { L"00001009", L"kbdca"},
        { L"0000100C", L"kbdsf_2"},
        { L"0000105F", L"kbdtifi"},
        { L"00001404", L"kbdus_6"},
        { L"00001409", L"kbdmaori"},
        { L"00001809", L"kbdir"},
        { L"0000201A", L"kbdbhc"},
        { L"00004009", L"kbdinen"},
        { L"00010401", L"kbda2"},
        { L"00010402", L"kbdus_1"},
        { L"00010405", L"kbdcz1"},
        { L"00010407", L"kbdgr1"},
        { L"00010408", L"kbdhe220"},
        { L"00010409", L"kbddv"},
        { L"0001040A", L"kbdes"},
        { L"0001040E", L"kbdhu1"},
        { L"00010410", L"kbdit142"},
        { L"00010415", L"kbdpl"},
        { L"00010416", L"kbdbr_2"},
        { L"00010418", L"kbdrost"},
        { L"00010419", L"kbdru1"},
        { L"0001041B", L"kbdsl1"},
        { L"0001041E", L"kbdth1"},
        { L"0001041F", L"kbdtuf"},
        { L"00010426", L"kbdlv1"},
        { L"00010427", L"kbdlt1"},
        { L"0001042F", L"kbdmacst"},
        { L"0001042B", L"kbdarmw"},
        { L"0001042C", L"kbdazst"},
        { L"0001042E", L"kbdsorex"},
        { L"00010437", L"kbdgeoqw"},
        { L"00010439", L"kbdinhin"},
        { L"0001043A", L"kbdmlt48"},
        { L"0001043B", L"kbdsmsno"},
        { L"00010444", L"kbdtt102"},
        { L"00010445", L"kbdinbe1"},
        { L"00010451", L"kbdtiprd"},
        { L"00010453", L"kbdkni"},
        { L"0001045C", L"kbdcherp"},
        { L"0001045D", L"kbdinuk2"},
        { L"0001045A", L"kbdsyr2"},
        { L"0001045B", L"kbdsw09"},
        { L"00010465", L"kbddiv2"},
        { L"00010480", L"kbdughr1"},
        { L"0001080C", L"kbdbene"},
        { L"0001083B", L"kbdfi1_1"},
        { L"00010850", L"kbdmonst"},
        { L"00010C00", L"kbdmyan_1"},
        { L"00011009", L"kbdcan"},
        { L"0001105F", L"kbdtifi2"},
        { L"00011809", L"kbdgae"},
        { L"00020401", L"kbda3"},
        { L"00020402", L"kbdbgph"},
        { L"00020405", L"kbdcz2"},
        { L"00020408", L"kbdhe319"},
        { L"00020409", L"kbdusx"},
        { L"0002040D", L"kbdhebl3"},
        { L"00020418", L"kbdropr"},
        { L"00020419", L"kbdrum"},
        { L"0002041E", L"kbdth2"},
        { L"00020422", L"kbdur1"},
        { L"00020426", L"kbdlvst"},
        { L"00020427", L"kbdlt2"},
        { L"0002042B", L"kbdarmph"},
        { L"0002042E", L"kbdsors1"},
        { L"00020437", L"kbdgeoer"},
        { L"00020445", L"kbdinbe2"},
        { L"00020449", L"kbdtam99"},
        { L"0002083B", L"kbdsmsfi"},
        { L"00020C00", L"kbdntl"},
        { L"00030402", L"kbdbulg"},
        { L"00030408", L"kbdhela2"},
        { L"00030409", L"kbdusl"},
        { L"0003041E", L"kbdth3"},
        { L"0003042B", L"kbdarmty"},
        { L"00030437", L"kbdgeome"},
        { L"00030449", L"kbdinen"},
        { L"00030C00", L"kbdtaile"},
        { L"00040402", L"kbdbgph1"},
        { L"00040408", L"kbdhela3"},
        { L"00040409", L"kbdusr"},
        { L"00040437", L"kbdgeooa"},
        { L"00040C00", L"kbdogham"},
        { L"00050408", L"kbdgkl"},
        { L"00050409", L"kbdusa"},
        { L"00050429", L"kbdfar"},
        { L"00060408", L"kbdhept"},
        { L"00070C00", L"kbdlisub"},
        { L"00080C00", L"kbdlisus"},
        { L"00090C00", L"kbdnko"},
        { L"000A0C00", L"kbdphags"},
        { L"000B0C00", L"kbdbug"},
        { L"000C0C00", L"kbdgthc"},
        { L"000D0C00", L"kbdolch"},
        { L"000E0C00", L"kbdosm"},
        { L"000F0C00", L"kbdoldit"},
        { L"00100C00", L"kbdsora"},
        { L"00110C00", L"kbdjav"},
        { L"00120C00", L"kbdfthrk"},
        { L"00130C00", L"kbdmyan_2"},
        { L"00140C00", L"kbdadlm"},
        { L"00150C00", L"kbdosa"},
    };

    std::wstring path;
    auto it = std::find_if(std::begin(known), std::end(known), [&pwszKLID](const auto& p) { return _wcsicmp(p.klid, pwszKLID) == 0; });
    if (it != std::end(known))
    {
        path = it->name;
    }

    wchar_t buf[MAX_PATH] = {};
    if (path.empty())
    {
        return buf;
    }

    swprintf_s(buf, std::size(buf), L"https://learn.microsoft.com/globalization/keyboards/%s", path.c_str());

    cache[pwszKLID] = buf;

    return buf;

}

std::wstring GetTSFProfileLink(const LCID& langId, const CLSID& clsId, const GUID& profileGuid)
{
    static std::map<LCID, std::wstring> cache;
    if (cache.find(langId) != cache.end())
    {
        return cache[langId];
    }

    struct KnownTSFProfiles
    {
        LCID langId;
        const WCHAR* name;
    } known[] =
    {
        { MAKELANGID(LANG_AMHARIC, SUBLANG_AMHARIC_ETHIOPIA), L"amharic-ime"},
        { MAKELANGID(LANG_BENGALI, SUBLANG_BENGALI_INDIA), L"bengali-ime"},
        { MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED), L"simplified-chinese-ime" },
        { MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_TRADITIONAL), L"traditional-chinese-ime"},
        { MAKELANGID(LANG_GUJARATI, SUBLANG_GUJARATI_INDIA), L"gujarati-ime"},
        { MAKELANGID(LANG_HINDI, SUBLANG_HINDI_INDIA), L"hindi-ime"},
        { MAKELANGID(LANG_JAPANESE, SUBLANG_JAPANESE_JAPAN), L"japanese-ime"},
        { MAKELANGID(LANG_KANNADA, SUBLANG_KANNADA_INDIA), L"kannada-ime"},
        { MAKELANGID(LANG_KOREAN, SUBLANG_KOREAN), L"korean-ime"},
        { MAKELANGID(LANG_MALAYALAM, SUBLANG_MALAYALAM_INDIA), L"malayalam-ime"},
        { MAKELANGID(LANG_MARATHI, SUBLANG_MARATHI_INDIA), L"marathi-ime"},
        { MAKELANGID(LANG_NEPALI, SUBLANG_HINDI_INDIA), L"hindi-ime"},
        { MAKELANGID(LANG_ODIA, SUBLANG_ODIA_INDIA), L"odia-ime"},
        { MAKELANGID(LANG_PUNJABI, SUBLANG_PUNJABI_INDIA), L"punjabi-ime"},
        { MAKELANGID(LANG_TAMIL, SUBLANG_TAMIL_INDIA), L"tamil-ime"},
        { MAKELANGID(LANG_TAMIL, SUBLANG_TAMIL_SRI_LANKA), L"tamil-ime" },
        { MAKELANGID(LANG_TELUGU, SUBLANG_TELUGU_INDIA), L"telugu-ime"},
        { MAKELANGID(LANG_TIGRINYA, SUBLANG_TIGRINYA_ETHIOPIA), L"tigrinya-ime"},
        { MAKELANGID(LANG_VIETNAMESE, SUBLANG_VIETNAMESE_VIETNAM), L"vietnamese-ime" },
        { MAKELANGID(LANG_YI, SUBLANG_YI_PRC), L"yi-ime"},
    };

    std::wstring path;
    auto it = std::find_if(std::begin(known), std::end(known), [langId](const auto& p) { return p.langId == langId; });
    if (it != std::end(known))
    {
        path = it->name;
    }

    wchar_t buf[MAX_PATH] = {};
    if (path.empty())
    {
        WORD lang = PRIMARYLANGID(langId);
        WORD subLang = SUBLANGID(langId);
        return buf;

    }

    swprintf_s(buf, std::size(buf), L"https://learn.microsoft.com/globalization/input/%s", path.c_str());

    cache[langId] = buf;

    return buf;
}

std::vector<std::wstring> EnumInstalledKeyboardLayouts()
{
    std::vector<std::wstring> layouts;

    HKEY key;
    CHECK_EQ(::RegOpenKeyExW(HKEY_LOCAL_MACHINE, KeyboardLayoutsRegistryPath, 0, KEY_READ, &key), ERROR_SUCCESS);

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

// Same as ITfInputProcessorProfiles::GetLanguageProfileDescription
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
                CHECK_EQ(::RegOpenKeyExW(profileKey, langIdStr, 0, KEY_READ, &langIdKey), ERROR_SUCCESS);

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

    wchar_t string[MAX_PATH] = {};
    CHECK(::GetLocaleInfoEx(localeName.c_str(), LOCALE_SENGLISHDISPLAYNAME, string, (int)std::size(string)) > 0);

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
    static std::map<std::wstring, std::wstring> cache;
    if (cache.find(localeName) != cache.end())
    {
        return cache[localeName];
    }

    wchar_t string[MAX_PATH] = {};
    CHECK(::GetLocaleInfoEx(localeName.c_str(), LOCALE_SKEYBOARDSTOINSTALL, string, (int)std::size(string)) > 0);

    cache[localeName] = string;

    return string;
}

// Get Display name in "<localeName>: <profileDisplayName> (<inputProfile>)" format.
// There are two types of <inputProfile> strings:
// <LangID>:{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
// <LangID>:<KLID>
// 
// Example output:
// sq-AL: Albanian (041C:0000041C)
// am-ET: Amharic Input Method 2 (045C:{7C472071-36A7-4709-88CC-859513E583A9}{9A4E8FC7-76BF-4A63-980D-FADDADF7E987})
std::wstring GetInputProfileDisplayName(const std::wstring& inputProfile, const std::wstring& inputProfileLanguage)
{
    std::wstring inputProfileNormalized = inputProfile;

    // normalize input profile to upper case
    utils::towupper(inputProfileNormalized);

    static std::map<std::wstring, std::wstring> cache;
    if (cache.find(inputProfileNormalized) != cache.end())
    {
        return cache[inputProfileNormalized];
    }

    auto inputProfileTokens = utils::split(inputProfileNormalized, L":", true);
    CHECK_EQ(inputProfileTokens.size(), 2);

    wchar_t* langIdStrTmp = nullptr;
    LANGID langId = static_cast<LANGID>(std::wcstoul(inputProfileTokens[0].c_str(), &langIdStrTmp, 16));
    CHECK(inputProfileTokens[0].c_str() != langIdStrTmp);

    // some languages doesn't have langId - use inputProfileLanguage as a fallback
    std::wstring language = (langId == LOCALE_CUSTOM_DEFAULT) ? inputProfileLanguage : GetLocaleName(langId);

    std::wstring profileDisplayName;
    if (inputProfileTokens[1].front() == L'{' && inputProfileTokens[1].back() == L'}') // TSF IME
    {
        std::wstring tsfInputProfile = inputProfileTokens[1];

        CHECK_EQ(tsfInputProfile.size(), utils::GetTSFProfileStringLength());
        const size_t guidLen = utils::GetGuidStringLength();

        CLSID clsId;
        CHECK_EQ(::CLSIDFromString(tsfInputProfile.substr(0, guidLen).c_str(), &clsId), NOERROR);

        GUID guid;
        CHECK_EQ(::IIDFromString(tsfInputProfile.substr(guidLen).c_str(), &guid), S_OK);

        std::wstring tsfProfileDisplayName = GetTSFProfileDisplayName(langId, clsId, guid);
        std::wstring tsfProfileLink = GetTSFProfileLink(langId, clsId, guid);

        wchar_t string[MAX_PATH] = {};
        if (!tsfProfileLink.empty())
        {
            swprintf_s(string, std::size(string), L"[%s](%s)", tsfProfileDisplayName.c_str(), tsfProfileLink.c_str());
        }
        else
        {
            swprintf_s(string, std::size(string), L"%s", tsfProfileDisplayName.c_str());
        }

        profileDisplayName = string;
    }
    else // KLID
    {
        std::wstring klid = inputProfileTokens[1];
        CHECK_EQ(klid.size(), KL_NAMELENGTH - 1);

        std::wstring layoutDisplayName = GetKeyboardLayoutDisplayName(klid.c_str());
        std::wstring layoutFileLink = GetKeyboardLayoutLink(klid.c_str());

        wchar_t string[MAX_PATH] = {};
        if (!layoutFileLink.empty())
        {
            swprintf_s(string, std::size(string), L"[%s keyboard](%s)", layoutDisplayName.c_str(), layoutFileLink.c_str());
        }
        else
        {
            swprintf_s(string, std::size(string), L"%s keyboard", layoutDisplayName.c_str());
        }

        profileDisplayName = string;
    }

    wchar_t string[1024] = {};
    swprintf_s(string, std::size(string), L"%s: %s (%s)", language.c_str(), profileDisplayName.c_str(), inputProfileNormalized.c_str());

    cache[inputProfileNormalized] = string;

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

    ::CoInitialize(0);

    // Keyboard identifiers
    // https://learn.microsoft.com/windows-hardware/manufacture/desktop/windows-language-pack-default-values#keyboard-identifiers
    {
        std::vector<std::wstring> layouts = EnumInstalledKeyboardLayouts();

        // Sort by Keyboard Layout Name string
        std::sort(layouts.begin(), layouts.end(), [](const auto& a, const auto& b) { return GetKeyboardLayoutDisplayName(a.c_str()) < GetKeyboardLayoutDisplayName(b.c_str());  });

        std::wcout << L"| Keyboard | Keyboard identifier |\n";
        std::wcout << L"|---|---|\n";
        for (auto& layout : layouts)
        {
            std::wstring layoutDisplayName = GetKeyboardLayoutDisplayName(layout.c_str());
            std::wstring layoutFileLink = GetKeyboardLayoutLink(layout.c_str());
            if (!layoutFileLink.empty())
            {
                layoutDisplayName = L"[" + layoutDisplayName + L"](" + layoutFileLink + L")";
            }
            std::wstring layoutNormalized = layout;
            utils::towupper(layoutNormalized);
            std::wcout << L"| " << layoutDisplayName << L" | " << layoutNormalized << L" |\n";
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
        std::wcout << L"|---|---|\n";
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
        std::wcout << L"|---|---|---|\n";

        int count = 0;
        for (const auto& locale : locales)
        {
            std::wstring keyboardsToInstall = GetKeyboardsToInstall(locale);
            std::wstring parentLocale = GetParentLocale(locale);
            if (parentLocale.empty())
            {
                // Skip input profiles that are same as in English language
                // 856 -> 800 locales on my system.
                if (locale != L"en" && keyboardsToInstall == GetKeyboardsToInstall(L"en"))
                    continue;
            }
            else
            {
                // Skip information for locales that have same keyboard layout profile as in corresponding parent locale.
                // 885 -> 349 locales on my system.
                if (keyboardsToInstall == GetKeyboardsToInstall(parentLocale))
                    continue;
            }

            std::wstring localeDisplayName = GetLocaleDisplayName(locale);
            std::wcout << L"| " /* << locale << L": "*/ << localeDisplayName << L" | ";

            auto inputProfiles = utils::split(keyboardsToInstall, L";", true);
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
            ++count;
        }

        std::wcout << L"Printed " << count << " languages out of " << locales.size() << L"\n";
    }

    return 0;
}
