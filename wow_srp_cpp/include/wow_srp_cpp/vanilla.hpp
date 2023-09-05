#pragma once

#include "wow_srp_cpp/wow_srp.hpp"
#include <cstdint>
#include <string>
#include <utility>
#include <memory>

struct WowSrpVanillaProofSeed;
struct WowSrpVanillaHeaderCrypto;

namespace wow_srp {

class VanillaProofSeed;

class VanillaHeaderCrypto {
public:
  VanillaHeaderCrypto() = delete;
  ~VanillaHeaderCrypto() = default;

  VanillaHeaderCrypto(const VanillaHeaderCrypto &) = delete;
  VanillaHeaderCrypto(VanillaHeaderCrypto &&) = default;

  VanillaHeaderCrypto &operator=(const VanillaHeaderCrypto &) = delete;
  VanillaHeaderCrypto &operator=(VanillaHeaderCrypto &&) = default;

  void encrypt(uint8_t *data, uint16_t length);
  void decrypt(uint8_t *data, uint16_t length);

private:
  friend VanillaProofSeed;
  explicit VanillaHeaderCrypto(WowSrpVanillaHeaderCrypto *inner) noexcept;

  std::unique_ptr<WowSrpVanillaHeaderCrypto, void(*)(WowSrpVanillaHeaderCrypto*)> m_inner;
};

class VanillaProofSeed {
public:
  VanillaProofSeed() noexcept;
  ~VanillaProofSeed() noexcept = default;

  VanillaProofSeed(const VanillaProofSeed &) = delete;
  VanillaProofSeed(VanillaProofSeed &&) = default;

  VanillaProofSeed &operator=(const VanillaProofSeed &) = delete;
  VanillaProofSeed &operator=(VanillaProofSeed &&) = default;

  [[nodiscard]] uint32_t proof_seed() const noexcept;

  std::pair<VanillaHeaderCrypto, ProofArray> into_client_header_crypto(
      const std::string &username,
      SessionKeyArray &session_key, uint32_t server_seed);

  VanillaHeaderCrypto into_server_header_crypto(
      const std::string &username,
      const SessionKeyArray &session_key,
      const ProofArray &client_proof, uint32_t client_seed);

private:
  std::unique_ptr<WowSrpVanillaProofSeed, void(*)(WowSrpVanillaProofSeed*)> m_inner;
  uint32_t m_seed;
};

} // namespace wow_srp