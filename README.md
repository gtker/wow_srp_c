# `wow_srp_c`

C bindings for the [`wow_srp` library](https://github.com/gtker/wow_srp) used for World of Warcraft authentication
server
key negotiation and world server header encryption/decryption.

Header files for both C (`wow_srp/wow_srp.h`) and C++ (`wow_srp/wow_srp.hpp`) are provided.
You should only use one of these, and probably the C++ one unless you know what you're doing.

## Quick Use for Cmake

* [Install Rust](https://www.rust-lang.org/tools/install).
* Add this repository to your project as
  either [a git submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules), [a git subtree](https://www.atlassian.com/git/tutorials/git-subtree),
  or just a straight copy.
* Add the following to your `CMakeLists.txt`:

```cmake
add_subdirectory(wow_srp_c)
target_compile_definitions(wow_srp INTERFACE # Optional
        #WOW_SRP_DISABLE_SERVER # Uncomment if you aren't writing a server
        #WOW_SRP_DISABLE_CLIENT # Uncomment if you aren't writing a client
        #WOW_SRP_DISABLE_VANILLA_HEADER # Uncomment if you don't use Vanilla (1.12)
        #WOW_SRP_DISABLE_TBC_HEADER # Uncomment if you don't use TBC (2.4.3)
        #WOW_SRP_DISABLE_WRATH_HEADER # Uncomment if you don't use Wrath (3.3.5)
)
target_link_libraries(YOUR_TARGET_HERE PRIVATE wow_srp::wow_srp)
```

* Import either the `wow_srp/wow_srp.h` or `wow_srp/wow_srp.hpp` header file.

## Slow use for everybody else

By default, both static libraries (`.a`/`.lib`) and shared libraries (`.so`/`.dll`) are built.

* [Install Rust](https://www.rust-lang.org/tools/install).
* Build the library with `cargo build --release`.
* Add the `include/` folder to your include path.
* Either add the `target/release` directory to your library path or copy the `target/release/wow_srp.(dll/so/a/lib)`
  files to your build directory.
* Add the necessary defines to disable symbols in the headers.
* Import either the `wow_srp/wow_srp.h` or `wow_srp/wow_srp.hpp` header file.

## Defines

| Define                           | Description                                                                                 |
|----------------------------------|---------------------------------------------------------------------------------------------|
| `WOW_SRP_DISABLE_SERVER`         | Disables types for the server part of authentication. Only used on authentication servers.  |
| `WOW_SRP_DISABLE_CLIENT`         | Disables types for the client part of authentication. Only used for clients.                |
| `WOW_SRP_DISABLE_VANILLA_HEADER` | Disables types for header encryption for Vanilla (1.12). Used by clients and world servers. | 
| `WOW_SRP_DISABLE_TBC_HEADER`     | Disables types for header encryption for TBC (2.4.3). Used by clients and world servers.    | 
| `WOW_SRP_DISABLE_WRATH_HEADER`   | Disables types for header encryption for Wrath (3.3.5). Used by clients and world servers.  | 

# Server Usage

## Authentication

Ensure the `WOW_SRP_DISABLE_SERVER` define is not set.

The general flow is:

```text
WowSrpVerifier -> WowSrpProof -> WowSrpServer
```

When creating users, generate a salt and password verifier from `wow_srp_verifier_from_username_and_password`.
Save these in the database.

When the client attempts a login, create a `WowSrpVerifier` from `wow_srp_verifier_from_database_values` and use the previously
stored salt and password verifier. Then convert it into a `WowSrpProof` with `wow_srp_verifier_into_proof`.

After receiving the client public key the `WowSrpProof` should be turned into a `WowSrpServer` with `wow_srp_proof_into_server`.

# Client Usage

Ensure the `WOW_SRP_DISABLE_CLIENT` define is not set.

The general flow is:

```text
WowSrpClientUser -> WowSrpClientChallenge -> WowSrpClient
```

Create a `WowSrpClientUser` through `wow_srp_client_user_from_username_and_password` with your username/password.
After receiving [CMD_AUTH_LOGON_CHALLENGE_Server](https://gtker.com/wow_messages/docs/cmd_auth_logon_challenge_server.html)
convert it toa `WowSrp`
