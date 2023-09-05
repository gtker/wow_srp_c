#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <string>

#include "wow_srp_cpp/wow_srp.hpp"

struct WowSrpVerifier;
struct WowSrpProof;
struct WowSrpServer;

namespace wow_srp {
class Proof;
class Server;

class Verifier {
public:
  Verifier(std::string &&username, const KeyArray &password_verifier,
           const KeyArray &salt);

  Verifier(const Verifier &) = delete;
  Verifier(Verifier &&) = default;

  Verifier &operator=(const Verifier &) = delete;
  Verifier &operator=(Verifier &&) = default;

  ~Verifier() = default;

  static Verifier from_username_and_password(std::string &&username,
                                             const std::string &password);

  [[nodiscard]] Proof into_proof() noexcept;

  [[nodiscard]] const KeyArray &salt() const noexcept;

  [[nodiscard]] const KeyArray &verifier() const noexcept;

private:
  std::string m_username;
  KeyArray m_salt;
  KeyArray m_verifier;
  std::unique_ptr<WowSrpVerifier, void (*)(WowSrpVerifier *)> m_inner;
};

class Proof {
public:
  Proof() = delete;
  Proof(const Proof &) = delete;
  Proof(Proof &&) = default;

  Proof &operator=(const Proof &) = delete;
  Proof &operator=(Proof &&) = default;

  ~Proof() = default;

  [[nodiscard]] const KeyArray &salt() const noexcept;
  [[nodiscard]] const KeyArray &server_public_key() const noexcept;

  Server into_server(const KeyArray &client_public_key,
                     const ProofArray &client_proof);

private:
  friend Verifier;
  Proof(WowSrpProof *inner, KeyArray salt, KeyArray server_public_key) noexcept;

  std::unique_ptr<WowSrpProof, void (*)(WowSrpProof *)> m_inner;
  KeyArray m_salt;
  KeyArray m_server_public_key;
};

class Server {
public:
  Server() = delete;
  Server(const Server &) = delete;
  Server(Server &&) = default;

  Server &operator=(const Server &) = delete;
  Server &operator=(Server &&) = default;

  ~Server() = default;

  [[nodiscard]] bool
  verify_reconnection_attempt(const ReconnectDataArray &client_data,
                              const ProofArray &client_proof);

  [[nodiscard]] const ProofArray &server_proof() const noexcept;
  [[nodiscard]] const SessionKeyArray &session_key() const noexcept;
  [[nodiscard]] const ReconnectDataArray &reconnect_data() const noexcept;

private:
  friend Proof;
  Server(WowSrpServer *inner, ProofArray server_proof,
         SessionKeyArray session_key,
         ReconnectDataArray reconnect_data) noexcept;

  std::unique_ptr<WowSrpServer, void (*)(WowSrpServer *)> m_inner;
  ProofArray m_server_proof;
  SessionKeyArray m_session_key;
  ReconnectDataArray m_reconnect_data;
};

} // namespace wow_srp