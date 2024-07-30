# Change Log

All notable changes to this project will be documented in this fil, 

peerbook adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

his file's format is define in 
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and the release workflow reads it to set github's release notes.

## [1.7.0] - 2023-12-12

### Added

- the support endpoint to send logs and description to support
- ICETCP server
- webexec status command to check the ICE server used

## [1.6.0] - 2023-12-05

### Added 

- Support for pure WebRTC connections 

## [1.5.1] - 2023-09-12

### Fixed

- restoring revenuecat API url escaping

### Changed

- license is now AGPLV3

## [1.5] - 2023-8-30

### Added

- `login` command for web clients support
- verify peer web page for the above command
- sending peers to clients upon verification

## [1.4] - 2023-8-15

### Added

- `rename` admin command to rename a peer
- `delete` admin command to delete a peer


## [1.3.1] - 2023-8-14

### Fixed 

- Private turn credentials

## [1.3] - 2023-8-9

### Added 

- A WebRTC endpoint, `/we`, for admin commands.
The client authenticates either through an Authorization header or if
its fingerprint is recognized. Here are the supported commands:
 - register <email> <peer_name> - once per user, returning a user id and a sixel QR code
 - verify <fingerprint> <otp>
 - ping [otp] - returning user id
- RevenueCat based authorization - supporting both Android and iOS clients
- base64 16 char long user id



## [1.2] - 2023-1-10

### Added

- Reading turn servers from redis

## [1.1.3]

### Added

- the `reset` command used to clear the online flag

### Fixed

- improved handling of our expired TURN provider
- extended ping time to 50sec

## [1.1.2] 2021-12-26

### Fixed

- timeouts on sunspace turn servers API
- home page URL 

## [1.1.1] 2021-12-07

### Fixed

- verification updates now affect connected peers

## [1.1] 2021-12-06

### Fixed

- Fixing offline webexec servers after `webexec restart`

### Aded

- the `/turn` API endpoint, returning turn servers

## [1.0.1] 2021-10-20

### Fixed 

- plain text email signature link
- email preferred format is html

## [1.0.0] 2021-10-20

### Added

- 2FA using one time password
- graphics design
- limitting peerbook to 10 entries


## [0.3.3] 2021-9-23

### Fixed

- email is now sent from support@tuzig.com


## [0.3.2] 2021-5-28

### Fixed

- `verify` field is alwats part of `peer_update` message
- improve texts

### Added

- Send no more than one email a minute to a user

## [0.3.1] 2021-5-22

### Fixed

- addinng a call to `make` to solve a rear panic
- better redis tiemouts
- gcp websocket timeout set to max

### Added

- return peerlist on reponse to a succesful post to verify


## [0.3.0] 2021-5-19

### Added

- stateless operations using redis pubsub
- `peer_update` message
- gcloud support
- REDIS_HOST env var instead of --redis

## [0.2.3] 2021-5-12

### Added 

- returning 409 on email mismatch

### Fixed 

- peer list to include only verified peers
- improved notifications

## [0.2.2] 2021-4-29

### Fixed

- refactoring connection management for stability & optimization
- returning 409 on mismatched email

## [0.2.1] 2021-4-26

### Fixed

- notifying unverified peers on authorization

## [0.2.0] 2021-4-26

### Added 

- smtp integration
- CORS
- verify endpoint
- home page with a form to send email
- `online` fieldon peers
- time fields on peers

## 0.1.0 - 2021-3-22

### Added 

- protocol documentation in README.md
- untested code covering all but auth changes
