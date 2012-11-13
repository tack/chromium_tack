// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/base64.h"
#include "base/string_number_conversions.h"
#include "base/string_tokenizer.h"
#include "base/string_util.h"
#include "net/http/http_security_headers.h"
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

// Parse the Strict-Transport-Security header, as currently defined in
// http://tools.ietf.org/html/draft-ietf-websec-strict-transport-sec-14:
//
// Strict-Transport-Security = "Strict-Transport-Security" ":"
//                             [ directive ]  *( ";" [ directive ] )
//
// directive                 = directive-name [ "=" directive-value ]
// directive-name            = token
// directive-value           = token | quoted-string
//
// 1.  The order of appearance of directives is not significant.
//
// 2.  All directives MUST appear only once in an STS header field.
//     Directives are either optional or required, as stipulated in
//     their definitions.
//
// 3.  Directive names are case-insensitive.
//
// 4.  UAs MUST ignore any STS header fields containing directives, or
//     other header field value data, that does not conform to the
//     syntax defined in this specification.
//
// 5.  If an STS header field contains directive(s) not recognized by
//     the UA, the UA MUST ignore the unrecognized directives and if the
//     STS header field otherwise satisfies the above requirements (1
//     through 4), the UA MUST process the recognized directives.
bool ParseHSTSHeader(const base::Time& now, const std::string& value,
                     base::Time* expiry,         // OUT
                     bool* include_subdomains) {  // OUT
  int max_age_candidate = 0;
  bool include_subdomains_candidate = false;

  // We must see max-age exactly once.
  int max_age_observed = 0;
  // We must see includeSubdomains exactly 0 or 1 times.
  int include_subdomains_observed = 0;

  enum ParserState {
    START,
    AFTER_MAX_AGE_LABEL,
    AFTER_MAX_AGE_EQUALS,
    AFTER_MAX_AGE,
    AFTER_INCLUDE_SUBDOMAINS,
    AFTER_UNKNOWN_LABEL,
    DIRECTIVE_END
  } state = START;

  StringTokenizer tokenizer(value, " \t=;");
  tokenizer.set_options(StringTokenizer::RETURN_DELIMS);
  tokenizer.set_quote_chars("\"");
  std::string unquoted;
  while (tokenizer.GetNext()) {
    DCHECK(!tokenizer.token_is_delim() || tokenizer.token().length() == 1);
    switch (state) {
      case START:
      case DIRECTIVE_END:
        if (IsAsciiWhitespace(*tokenizer.token_begin()))
          continue;
        if (LowerCaseEqualsASCII(tokenizer.token(), "max-age")) {
          state = AFTER_MAX_AGE_LABEL;
          max_age_observed++;
        } else if (LowerCaseEqualsASCII(tokenizer.token(),
                                        "includesubdomains")) {
          state = AFTER_INCLUDE_SUBDOMAINS;
          include_subdomains_observed++;
          include_subdomains_candidate = true;
        } else {
          state = AFTER_UNKNOWN_LABEL;
        }
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
        unquoted = HttpUtil::Unquote(tokenizer.token());
        if (!MaxAgeToInt(unquoted.begin(),
                         unquoted.end(),
                         &max_age_candidate))
          return false;
        state = AFTER_MAX_AGE;
        break;

      case AFTER_MAX_AGE:
      case AFTER_INCLUDE_SUBDOMAINS:
        if (IsAsciiWhitespace(*tokenizer.token_begin()))
          continue;
        else if (*tokenizer.token_begin() == ';')
          state = DIRECTIVE_END;
        else
          return false;
        break;

      case AFTER_UNKNOWN_LABEL:
        // Consume and ignore the post-label contents (if any).
        if (*tokenizer.token_begin() != ';')
          continue;
        state = DIRECTIVE_END;
        break;
    }
  }

  // We've consumed all the input.  Let's see what state we ended up in.
  if (max_age_observed != 1 ||
      (include_subdomains_observed != 0 && include_subdomains_observed != 1)) {
    return false;
  }

  switch (state) {
    case AFTER_MAX_AGE:
    case AFTER_INCLUDE_SUBDOMAINS:
    case AFTER_UNKNOWN_LABEL:
      *expiry = now + base::TimeDelta::FromSeconds(max_age_candidate);
      *include_subdomains = include_subdomains_candidate;
      return true;
    case START:
    case DIRECTIVE_END:
    case AFTER_MAX_AGE_LABEL:
    case AFTER_MAX_AGE_EQUALS:
      return false;
    default:
      NOTREACHED();
      return false;
  }
}

// Strip, Split, StringPair, and ParsePins are private implementation details
// of ParsePinsHeader(std::string&, DomainState&).
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
bool ParseHPKPHeader(const base::Time& now,
                     const std::string& value,
                     base::Time* expiry,
                     HashValueVector* hashes) {
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

  if (!parsed_max_age)
    return false;

  *expiry = now + base::TimeDelta::FromSeconds(max_age_candidate);
  for (HashValueVector::const_iterator i = pins.begin();
       i != pins.end(); ++i) {
    hashes->push_back(*i);
  }

  return true;
}

}  // namespace net

