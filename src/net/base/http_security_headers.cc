
#include "net/base/http_security_headers.h"
#include "base/base64.h"
#include "base/string_number_conversions.h"
#include "base/string_tokenizer.h"
#include "base/string_util.h"
#include "net/http/http_util.h"


namespace net {

// MaxAgeToInt converts a string representation of a number of seconds into a
// int. We use strtol in order to handle overflow correctly. The string may
// contain an arbitary number which we should truncate correctly rather than
// throwing a parse failure.
static bool MaxAgeToInt(std::string::const_iterator begin,
                        std::string::const_iterator end,
                        int* result) {
  const std::string s(begin, end);
  char* endptr;
  long int i = strtol(s.data(), &endptr, 10 /* base */);
  if (*endptr || i < 0)
    return false;
  if (i > kMaxHSTSAgeSecs)
    i = kMaxHSTSAgeSecs;
  *result = i;
  return true;
}

// "Strict-Transport-Security" ":"
//     "max-age" "=" delta-seconds [ ";" "includeSubDomains" ]
bool ParseHSTSHeader(
  const base::Time& now,
  const std::string& value,
  bool* present,               
  base::Time* expiry,         
  bool* include_subdomains) {
  int max_age_candidate = 0;

  enum ParserState {
    START,
    AFTER_MAX_AGE_LABEL,
    AFTER_MAX_AGE_EQUALS,
    AFTER_MAX_AGE,
    AFTER_MAX_AGE_INCLUDE_SUB_DOMAINS_DELIMITER,
    AFTER_INCLUDE_SUBDOMAINS,
  } state = START;

  StringTokenizer tokenizer(value, " \t=;");
  tokenizer.set_options(StringTokenizer::RETURN_DELIMS);
  while (tokenizer.GetNext()) {
    DCHECK(!tokenizer.token_is_delim() || tokenizer.token().length() == 1);
    switch (state) {
      case START:
        if (IsAsciiWhitespace(*tokenizer.token_begin()))
          continue;
        if (!LowerCaseEqualsASCII(tokenizer.token(), "max-age"))
          return false;
        state = AFTER_MAX_AGE_LABEL;
        break;

      case AFTER_MAX_AGE_LABEL:
        if (IsAsciiWhitespace(*tokenizer.token_begin()))
          continue;
        if (*tokenizer.token_begin() != '=')
          return false;
        DCHECK_EQ(tokenizer.token().length(), 1U);
        state = AFTER_MAX_AGE_EQUALS;
        break;

      case AFTER_MAX_AGE_EQUALS:
        if (IsAsciiWhitespace(*tokenizer.token_begin()))
          continue;
        if (!MaxAgeToInt(tokenizer.token_begin(),
                         tokenizer.token_end(),
                         &max_age_candidate))
          return false;
        state = AFTER_MAX_AGE;
        break;

      case AFTER_MAX_AGE:
        if (IsAsciiWhitespace(*tokenizer.token_begin()))
          continue;
        if (*tokenizer.token_begin() != ';')
          return false;
        state = AFTER_MAX_AGE_INCLUDE_SUB_DOMAINS_DELIMITER;
        break;

      case AFTER_MAX_AGE_INCLUDE_SUB_DOMAINS_DELIMITER:
        if (IsAsciiWhitespace(*tokenizer.token_begin()))
          continue;
        if (!LowerCaseEqualsASCII(tokenizer.token(), "includesubdomains"))
          return false;
        state = AFTER_INCLUDE_SUBDOMAINS;
        break;

      case AFTER_INCLUDE_SUBDOMAINS:
        if (!IsAsciiWhitespace(*tokenizer.token_begin()))
          return false;
        break;
    }
  }

  if (state == AFTER_INCLUDE_SUBDOMAINS || state == AFTER_MAX_AGE) {
    *present = true;
    *expiry = now + base::TimeDelta::FromSeconds(max_age_candidate);
    *include_subdomains = (state == AFTER_INCLUDE_SUBDOMAINS);    
    return true;
  }
  return false;
}

// Returns true iff there is an item in |pins| which is not present in
// |from_cert_chain|. Such an SPKI hash is called a "backup pin".
static bool IsBackupPinPresent(const HashValueVector& pins,
                               const HashValueVector& from_cert_chain) {
  for (HashValueVector::const_iterator i = pins.begin(); 
       i != pins.end(); ++i) {
    HashValueVector::const_iterator j =
      std::find(from_cert_chain.begin(), from_cert_chain.end(), *i);
    if (j == from_cert_chain.end())
      return true;
  }

  return false;
}

// Returns true iff |pins| contains both a live and a backup pin. A live pin
// is a pin whose SPKI is present in the certificate chain in |ssl_info|. A
// backup pin is a pin intended for disaster recovery, not day-to-day use, and
// thus must be absent from the certificate chain. The Public-Key-Pins header
// specification requires both.
static bool IsPinListValid(const HashValueVector& pins,
                           const SSLInfo& ssl_info) {
  // Fast fail: 1 live + 1 backup = at least 2 pins. (Check for actual
  // liveness and backupness below.)
  if (pins.size() < 2)
    return false;

  const HashValueVector& from_cert_chain = ssl_info.public_key_hashes;
  if (from_cert_chain.empty())
    return false;

  return IsBackupPinPresent(pins, from_cert_chain) &&
         HashesIntersect(pins, from_cert_chain);
}

// Strip, Split, StringPair, and ParsePins are private implementation details
// of ParseHPKPHeader.
static std::string Strip(const std::string& source) {
  if (source.empty())
    return source;

  std::string::const_iterator start = source.begin();
  std::string::const_iterator end = source.end();
  HttpUtil::TrimLWS(&start, &end);
  return std::string(start, end);
}

typedef std::pair<std::string, std::string> StringPair;

static StringPair Split(const std::string& source, char delimiter) {
  StringPair pair;
  size_t point = source.find(delimiter);

  pair.first = source.substr(0, point);
  if (std::string::npos != point)
    pair.second = source.substr(point + 1);

  return pair;
}


static bool ParseAndAppendPin(const std::string& value,
                              HashValueTag tag,
                              HashValueVector* hashes) {
  std::string unquoted = HttpUtil::Unquote(value);
  std::string decoded;

  // This code has to assume that 32 bytes is SHA-256 and 20 bytes is SHA-1.
  // Currently, those are the only two possibilities, so the assumption is
  // valid.
  if (!base::Base64Decode(unquoted, &decoded))
    return false;

  HashValue hash(tag);
  if (decoded.size() != hash.size())
    return false;

  memcpy(hash.data(), decoded.data(), hash.size());
  hashes->push_back(hash);
  return true;
}

// "Public-Key-Pins" ":"
//     "max-age" "=" delta-seconds ";"
//     "pin-" algo "=" base64 [ ";" ... ]
bool ParseHPKPHeader(
    const base::Time& now,
    const std::string& value,
    const SSLInfo& ssl_info,
    HashValueVector* hashes,
    bool* present,
    base::Time* expiry) {
  bool parsed_max_age = false;
  int max_age_candidate = 0;
  HashValueVector pins;

  std::string source = value;

  while (!source.empty()) {
    StringPair semicolon = Split(source, ';');
    semicolon.first = Strip(semicolon.first);
    semicolon.second = Strip(semicolon.second);
    StringPair equals = Split(semicolon.first, '=');
    equals.first = Strip(equals.first);
    equals.second = Strip(equals.second);

    if (LowerCaseEqualsASCII(equals.first, "max-age")) {

      if (equals.second.empty() ||
          !MaxAgeToInt(equals.second.begin(), equals.second.end(),
                       &max_age_candidate)) {
        return false;
      }
      parsed_max_age = true;
    } else if (StartsWithASCII(equals.first, "pin-", false)) {
      HashValueTag tag;
      if (LowerCaseEqualsASCII(equals.first, "pin-sha1")) {
        tag = HASH_VALUE_SHA1;
      } else if (LowerCaseEqualsASCII(equals.first, "pin-sha256")) {
        tag = HASH_VALUE_SHA256;
      } else {
        return false;
      }
      if (!ParseAndAppendPin(equals.second, tag, &pins)) {
        return false;
      }
    } else {
      // Silently ignore unknown directives for forward compatibility.
    }

    source = semicolon.second;
  }

  if (!parsed_max_age || !IsPinListValid(pins, ssl_info)) {
    return false;
  }

  *present = true;
  *expiry = now + base::TimeDelta::FromSeconds(max_age_candidate);
  for (HashValueVector::const_iterator i = pins.begin();
       i != pins.end(); ++i) {
    hashes->push_back(*i);
  }

  return true;
}

bool SPKIHashesFromListValue(const ListValue& pins, HashValueVector* hashes) {
  size_t num_pins = pins.GetSize();
  for (size_t i = 0; i < num_pins; ++i) {
    std::string type_and_base64;
    HashValue fingerprint;
    if (!pins.GetString(i, &type_and_base64))
      return false;
    if (!fingerprint.ParsePin(type_and_base64))
      return false;
      hashes->push_back(fingerprint);
  }
  return true;
}

ListValue* SPKIHashesToListValue(const HashValueVector& hashes) {
  ListValue* pins = new ListValue;
  for (HashValueVector::const_iterator i = hashes.begin(); i != hashes.end(); ++i)
    pins->Append(new StringValue(i->WriteAsPin()));
  return pins;
}


}
