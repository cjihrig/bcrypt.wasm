#include <emscripten.h>
#include <emscripten/bind.h>
#include "node_blf.h"

using namespace emscripten;


inline bool CompareStrings(const char* s1, const char* s2) {
  bool eq = true;
  const int s1_len = strlen(s1);
  const int s2_len = strlen(s2);

  if (s1_len != s2_len) {
    eq = false;
  }

  const int max_len = (s2_len < s1_len) ? s1_len : s2_len;

  // To prevent timing attacks, check entire string, even if found to be false.
  for (int i = 0; i < max_len; ++i) {
    if (s1_len >= i && s2_len >= i && s1[i] != s2[i]) {
      eq = false;
    }
  }

  return eq;
}


bool ValidateSalt(const char* salt) {
  if (!salt || *salt != '$') {
    return false;
  }

  // Discard $
  salt++;

  if (*salt > BCRYPT_VERSION) {
    return false;
  }

  if (salt[1] != '$') {
    switch (salt[1]) {
      case 'a':
      case 'b':
        salt++;
        break;
      default:
        return false;
    }
  }

  // Discard version + $
  salt += 2;

  if (salt[2] != '$') {
    return false;
  }

  const int n = atoi(salt);

  if (n > 31 || n < 0) {
    return false;
  }

  if (((uint8_t) 1 << (uint8_t) n) < BCRYPT_MINROUNDS) {
    return false;
  }

  salt += 3;

  if (strlen(salt) * 3 / 4 < BCRYPT_MAXSALT) {
    return false;
  }

  return true;
}


bool CompareSync(const std::string pw, const std::string hash) {
  char bcrypted[_PASSWORD_LEN];

  if (ValidateSalt(hash.c_str())) {
    bcrypt(pw.c_str(), hash.c_str(), bcrypted);
    return CompareStrings(bcrypted, hash.c_str());
  }

  return false;
}


std::string EncryptSync(const std::string data, const std::string salt) {
  if (!ValidateSalt(salt.c_str())) {
    EM_ASM(
      throw new Error(
        'salt must be of the form: $Vers$log2(NumRounds)$saltvalue'
      );
    );
    return nullptr;
  }

  char bcrypted[_PASSWORD_LEN];
  bcrypt(data.c_str(), salt.c_str(), bcrypted);
  return std::string(bcrypted);
}


std::string GenerateSaltSync(const int32_t rounds, const std::string seed_str) {
  if (seed_str.length() != 16) {
    EM_ASM(
      throw new Error('seed must be a 16 byte buffer');
    );
    return nullptr;
  }

  u_int8_t* seed = (u_int8_t*) seed_str.c_str();
  char salt[_SALT_LEN];
  bcrypt_gensalt(rounds, seed, salt);
  return std::string(salt);
}


u_int32_t GetRounds(const std::string hash) {
  u_int32_t rounds;

  if (!(rounds = bcrypt_get_rounds(hash.c_str()))) {
    EM_ASM(
      throw new Error('invalid hash provided');
    );
    return 0;
  }

  return rounds;
}


EMSCRIPTEN_BINDINGS(bcrypt) {
  function("CompareSync", &CompareSync);
  function("EncryptSync", &EncryptSync);
  function("GenerateSaltSync", &GenerateSaltSync);
  function("GetRounds", &GetRounds);
}
