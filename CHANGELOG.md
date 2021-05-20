# Change Log

All notable changes to this project will be documented in this fil, 

webexec adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

his file's format is define in 
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and the release workflow reads it to set github's release notes.


## Unreleased

### Fixed

- addinng a call to `make` to solve a rear panic


### Added

- return peerlist on reponse to a succesful post to verify


## [0.3.0] 2020-5-19

### Added

- stateless operations using redis pubsub
- `peer_update` message
- gcloud support
- REDIS_HOST env var instead of --redis

## [0.2.3] 2020-5-12

### Added 

- returning 409 on email mismatch

### Fixed 

- peer list to include only verified peers
- improved notifications

## [0.2.2] 2020-4-29

### Fixed

- refactoring connection management for stability & optimization
- returning 409 on mismatched email

## [0.2.1] 2020-4-26

### Fixed

- notifying unverified peers on authorization

## [0.2.0] 2020-4-26

### Added 

- smtp integration
- CORS
- verify endpoint
- home page with a form to send email
- `online` fieldon peers
- time fields on peers

## 0.1.0 - 2020-3-22

### Added 

- protocol documentation in README.md
- untested code covering all but auth changes
