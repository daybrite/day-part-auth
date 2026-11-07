<!--
Copyright © The Daybrite Project
SPDX-License-Identifier: MPL-2.0
-->

# day-part-auth

Connect accounts through system sign-in surfaces, OAuth/OpenID Connect, and passkeys.

[Day](https://daybrite.dev/docs/) is a Rust framework for building apps with native desktop and
mobile controls, plus HTML controls on the web.

The app owns its session and token storage. This release is experimental; review the guide’s
account-security limitations before integrating a provider.

## Use

Add `day-part-auth = "0.*"` to your app’s `[dependencies]`.
Follow the setup guide for platform requirements and initialization.

## Documentation

- [Setup and usage guide](https://daybrite.dev/docs/reference/auth/)
- [Rust API](https://docs.rs/day-part-auth/0.1.0/day_part_auth/)
- [Crates.io](https://crates.io/crates/day-part-auth)
- [Run the demo](demo/README.md)

[Source](https://github.com/daybrite/day-part-auth) · [MPL-2.0 license](https://github.com/daybrite/day-part-auth/blob/main/LICENSE)
