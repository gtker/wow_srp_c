#pragma once
#include "wow_srp_cpp/wow_srp.hpp"
#include <array>
#include <cstdint>
#include <string>
#include <memory>

struct WowSrpClientChallenge;
struct WowSrpClient;

namespace wow_srp {
class Client;

class ClientChallenge {
public:
  ClientChallenge(const std::string &username, const std::string &password,
                  uint8_t generator,
                  KeyArray large_safe_prime,
                  KeyArray server_public_key,
                  KeyArray salt);

  ClientChallenge(const ClientChallenge &) = delete;
  ClientChallenge(ClientChallenge &&) = default;

  ClientChallenge &operator=(const ClientChallenge &) = delete;
  ClientChallenge &operator=(ClientChallenge &&) = default;

  ~ClientChallenge() = default;

  Client verify_server_proof(ProofArray server_proof);

  [[nodiscard]] const KeyArray &
  client_public_key() const noexcept;
  [[nodiscard]] const ProofArray &
  client_proof() const noexcept;

private:
  std::unique_ptr<WowSrpClientChallenge, void(*)(WowSrpClientChallenge*)> m_inner;
  KeyArray m_client_public_key;
  ProofArray m_client_proof;
};

class Client {
public:
  Client() = delete;
  ~Client() = default;
  Client(const Client&) = delete;
  Client(Client&&) = default;

  Client &operator=(const Client&) = delete;
  Client& operator=(Client&&) = default;

  [[nodiscard]] const SessionKeyArray& session_key() const noexcept;
  [[nodiscard]] std::pair<ReconnectDataArray, ProofArray> calculate_reconnect_values(ReconnectDataArray server_challenge_data);

private:
  friend ClientChallenge;
  Client(WowSrpClient* inner, SessionKeyArray session_key);

  std::unique_ptr<WowSrpClient, void(*)(WowSrpClient*)> m_inner;
  SessionKeyArray m_session_key;
};

} // namespace wow_srp