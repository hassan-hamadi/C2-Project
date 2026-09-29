# Third-party notices

## xray-core REALITY client

`agent/funcs/reality/reality.go` is adapted from the REALITY client implementation in [XTLS/Xray-core](https://github.com/XTLS/Xray-core/blob/main/transport/internet/reality/reality.go). It was modified for this project in 2026 to remove xray-core framework dependencies and integrate with the project's Go transport.

That source file is subject to the [Mozilla Public License 2.0](https://www.mozilla.org/MPL/2.0/). The adapted file includes the MPL notice and modification/source information. Changes to that covered file must continue to be made available under MPL 2.0 when distributed as required by that license.

Other Go and Python dependencies retain their respective upstream licenses. They are referenced through `agent/go.mod`, `agent/go.sum`, and `requirements.txt`; their source is not vendored in this repository.
