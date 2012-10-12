
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
  if (i > TransportSecurityState::kMaxHSTSAgeSecs)
    i = TransportSecurityState::kMaxHSTSAgeSecs;
  *result = i;
  return true;
}

// static
const char* TransportSecurityState::HashValueLabel(
    const HashValue& hash_value) {
  switch (hash_value.tag) {
    case HASH_VALUE_SHA1:
      return "sha1/";
    case HASH_VALUE_SHA256:
      return "sha256/";
    default:
      NOTREACHED();
      LOG(WARNING) << "Invalid fingerprint of unknown type " << hash_value.tag;
      return "unknown/";
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

// static
bool TransportSecurityState::ParsePin(const std::string& value,
                                      HashValue* out) {
  StringPair slash = Split(Strip(value), '/');

  if (slash.first == "sha1")
    out->tag = HASH_VALUE_SHA1;
  else if (slash.first == "sha256")
    out->tag = HASH_VALUE_SHA256;
  else
    return false;

  std::string decoded;
  if (!base::Base64Decode(slash.second, &decoded) ||
      decoded.size() != out->size()) {
    return false;
  }

  memcpy(out->data(), decoded.data(), out->size());
  return true;
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

struct HashValuesEqualPredicate {
  explicit HashValuesEqualPredicate(const HashValue& fingerprint) :
      fingerprint_(fingerprint) {}

  bool operator()(const HashValue& other) const {
    return fingerprint_.Equals(other);
  }

  const HashValue& fingerprint_;
};

// Returns true iff there is an item in |pins| which is not present in
// |from_cert_chain|. Such an SPKI hash is called a "backup pin".
static bool IsBackupPinPresent(const HashValueVector& pins,
                               const HashValueVector& from_cert_chain) {
  for (HashValueVector::const_iterator
       i = pins.begin(); i != pins.end(); ++i) {
    HashValueVector::const_iterator j =
        std::find_if(from_cert_chain.begin(), from_cert_chain.end(),
                     HashValuesEqualPredicate(*i));
      if (j == from_cert_chain.end())
        return true;
  }

  return false;
}

// Returns true if the intersection of |a| and |b| is not empty. If either
// |a| or |b| is empty, returns false.
static bool HashesIntersect(const HashValueVector& a,
                            const HashValueVector& b) {
  for (HashValueVector::const_iterator i = a.begin(); i != a.end(); ++i) {
    HashValueVector::const_iterator j =
        std::find_if(b.begin(), b.end(), HashValuesEqualPredicate(*i));
    if (j != b.end())
      return true;
  }

  return false;
}

static std::string HashesToBase64String(
    const HashValueVector& hashes) {
  std::vector<std::string> hashes_strs;
  for (HashValueVector::const_iterator
       i = hashes.begin(); i != hashes.end(); i++) {
    std::string s;
    const std::string hash_str(reinterpret_cast<const char*>(i->data()),
                               i->size());
    base::Base64Encode(hash_str, &s);
    hashes_strs.push_back(s);
  }

  return JoinString(hashes_strs, ',');
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

// "Public-Key-Pins" ":"
//     "max-age" "=" delta-seconds ";"
//     "pin-" algo "=" base64 [ ";" ... ]
bool TransportSecurityState::DomainState::ParseHPKPHeader(
    const base::Time& now,
    const std::string& value,
    const SSLInfo& ssl_info) {
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
      if (max_age_candidate > kMaxHSTSAgeSecs)
        max_age_candidate = kMaxHSTSAgeSecs;
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

  dynamic_spki_hashes_expiry =
      now + base::TimeDelta::FromSeconds(max_age_candidate);

  dynamic_spki_hashes.clear();
  if (max_age_candidate > 0) {
    for (HashValueVector::const_iterator i = pins.begin();
         i != pins.end(); ++i) {
      dynamic_spki_hashes.push_back(*i);
    }
  }

  return true;
}

// "Strict-Transport-Security" ":"
//     "max-age" "=" delta-seconds [ ";" "includeSubDomains" ]
bool TransportSecurityState::DomainState::ParseHSTSHeader(
  const base::Time& now,
  const std::string& value
  bool present,               
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

  // We've consumed all the input.  Let's see what state we ended up in.
  switch (state) {
    case START:
    case AFTER_MAX_AGE_LABEL:
    case AFTER_MAX_AGE_EQUALS:
      return false;
    case AFTER_MAX_AGE:
      upgrade_expiry =
          now + base::TimeDelta::FromSeconds(max_age_candidate);
      include_subdomains = false;
      upgrade_mode = MODE_FORCE_HTTPS;
      return true;
    case AFTER_MAX_AGE_INCLUDE_SUB_DOMAINS_DELIMITER:
      return false;
    case AFTER_INCLUDE_SUBDOMAINS:
      upgrade_expiry =
          now + base::TimeDelta::FromSeconds(max_age_candidate);
      include_subdomains = true;
      upgrade_mode = MODE_FORCE_HTTPS;
      return true;
    default:
      NOTREACHED();
      return false;
  }
}

static bool AddHash(const std::string& type_and_base64,
                    HashValueVector* out) {
  HashValue hash;

  if (!TransportSecurityState::ParsePin(type_and_base64, &hash))
    return false;

  out->push_back(hash);
  return true;
}
