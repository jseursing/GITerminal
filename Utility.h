#pragma once
#include <string>
#include <vector>
#include <Windows.h>

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: Tokenize
//
/////////////////////////////////////////////////////////////////////////////////////////
static std::vector<std::string> Tokenize(std::string str, const char* delim)
{
  std::vector<std::string> tokens;

  size_t base = 0;
  size_t next = str.find_first_of(delim, base);
  while (std::string::npos != next)
  {
    if (base != next)
    {
      tokens.push_back(str.substr(base, next - base));
    }

    base = next + 1;
    next = str.find_first_of(delim, base);
  }

  // Add remainder of string if base is not at the end..
  if (base < str.length())
  {
    tokens.push_back(str.substr(base));
  }

  return tokens;
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: StrReplace
//
/////////////////////////////////////////////////////////////////////////////////////////
static void StrReplace(const char* delim,
                       const char* rep,
                       std::string& str,
                       unsigned int count)
{
  unsigned int counter = 0;
  size_t next = str.find(delim);
  while (std::string::npos != next)
  {
    std::string temp; 
    if (0 == memcmp(delim, str.substr(next).c_str(), strlen(delim)))
    {
      temp = str.substr(0, next) + str.substr(next + strlen(delim));
      ++counter;
    }
    else
    {
      temp = str.substr(0, next) + str.substr(next + 1);
    }

    str = temp;
    next = str.find(delim);

    // Exit if we exceed count
    if ((0 < count) && (counter >= count))
    {
      break;
    }
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: StrUpper
//
/////////////////////////////////////////////////////////////////////////////////////////
static void StrUpper(std::string& str)
{
  for (unsigned int i = 0; i < str.length(); ++i)
  {
    if ((0x61 <= str[i]) && (0x7A >= str[i]))
    {
      str[i] -= 0x20;
    }
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: StrLower
//
/////////////////////////////////////////////////////////////////////////////////////////
static void StrLower(std::string& str)
{
  for (unsigned int i = 0; i < str.length(); ++i)
  {
    if ((0x41 <= str[i]) && (0x5A >= str[i]))
    {
      str[i] += 0x20;
    }
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: ByteArrayToString
//
/////////////////////////////////////////////////////////////////////////////////////////
static std::string ByteArrayToString(unsigned char* data, unsigned int len)
{
  std::string output = "";

  for (unsigned int i = 0; i < len; ++i)
  {
    char temp[6] = {0};
    sprintf_s(temp, "%02X ", static_cast<unsigned char>(data[i]));
    output += temp;
  }

  return output;
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: ReadBuf
//
/////////////////////////////////////////////////////////////////////////////////////////
template<typename T>
__inline T ReadBuf(unsigned char* src, unsigned int* idx)
{
  T value = *reinterpret_cast<T*>(&src[*idx]);
  *idx += sizeof(T);
  return value;
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: ValueScan
//
/////////////////////////////////////////////////////////////////////////////////////////
template<typename T>
std::vector<unsigned int> ValueScan(unsigned char* src, unsigned int len, T target)
{
  std::vector<unsigned int> offsets;

  T* ptr = reinterpret_cast<T*>(src);
  for (unsigned int i = 0; i < (len / sizeof(T)); ++i)
  {
    if (ptr[i] == target)
    {
      offsets.push_back(i);
    }
  }

  return offsets;
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: EnableDebugPriv
//
/////////////////////////////////////////////////////////////////////////////////////////
static bool SetDebugPriv(bool enable)
{
  HANDLE tokenHandle = INVALID_HANDLE_VALUE;

  TOKEN_PRIVILEGES tokenPrivs;
  if (false == OpenProcessToken(GetCurrentProcess(), 
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
                                &tokenHandle))
  {
    return false;
  }

  bool success = false;
  if (TRUE == LookupPrivilegeValue(0, SE_DEBUG_NAME, &(tokenPrivs.Privileges[0].Luid)))
  {
    tokenPrivs.PrivilegeCount = 1;
    tokenPrivs.Privileges[0].Attributes = 
      (true == enable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED);
    AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPrivs, 0, 0, 0);
    success = (ERROR_SUCCESS == GetLastError());
  }

  CloseHandle(tokenHandle);
  return success;
}