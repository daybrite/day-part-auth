<!--
Copyright © The Daybrite Project
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Auth Demo

The demo and on-device test app for [`day-part-auth`](..): one page with an OpenID Connect
sign-in against a provider the app runs on loopback, the token lifecycle, passkeys, Sign in with
Apple, and Google. It depends on the part by path (`day-part-auth = { path = ".." }`), so a change
to the part and a change here land in one pull request and one CI run.

## Run it

```sh
day doctor                                            # the toolchains for the targets below
day launch -p macos-appkit --script dayscript/auth.yaml
day launch -p ios-uikit --script dayscript/auth.yaml
day launch -p android-mdc --script dayscript/auth.yaml
```

The script is the test: it signs in silently (`prompt=none`, an HTTP client standing in for the
browser), checks the verified ID token's claims on the status line, reads userinfo, refreshes,
revokes, signs out, and captures two screenshots under `build/day/screenshots/<target>/`. CI runs
exactly this on every target in [../.github/workflows/ci.yml](../.github/workflows/ci.yml). The
browser sign-in and the system sheets are the part a script cannot pass: press **Sign in** yourself
and the system's auth browser opens on the provider's consent page.

## Build against a local day

No `Cargo.lock` is committed: the first build resolves day at the tip of `main`, and `cargo
update` moves it there again. To build against a checkout of day instead:

```sh
day patch --local ../../day             # writes .cargo/config.toml, gitignored
day patch --check                       # every day crate now resolves from the checkout
```

Delete `.cargo/config.toml` to go back to the git dependency.

## Generated native projects

Xcode project documents, Android Gradle files, and HarmonyOS hvigor files are created under
`build/` by `day prepare`, `day build`, and `day launch`. Open the selected project with
`day open -t <target>`; edits to generated files are disposable. The Swift sources, plists and
`.xcconfig` files under `platform/` are the app's own.
