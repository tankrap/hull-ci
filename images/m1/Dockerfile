# The default sandbox image (`HULL_CI_IMAGE`, default `hull-ci/m1:latest`).
#
# Built locally and published to no registry, on purpose. The image a job runs in is the inside of
# the box, and pulling it from a third party at job time would make an outside party's tag part of
# the isolation story — see design D§7.2. Building it here keeps the contents auditable in the same
# repository as the runner that starts it.
#
#     docker build -t hull-ci/m1:latest images/m1
#
# What has to be in it is decided by autodetection (design D§6, `hull-ci-node/src/detect.rs`), which
# looks for a `Makefile` `test` target, `run-tests.sh`, `package.json`, `Cargo.toml`, and falls back
# to a shell. So the floor is: a POSIX shell, `make`, and nothing else claimed.
#
# Deliberately NOT here: language toolchains. A pipeline that needs one names its own image
# (`image("rust:1.83")` in `.hull/ci.star`) rather than growing this one, because every tool added
# here is a tool every job on the fleet runs with.
FROM alpine:3.21

RUN apk add --no-cache make

# The runner overrides ENTRYPOINT and passes `--user`, so neither is a control here (see
# `container.rs`: the image must not be able to wrap, alter, or ignore the command). This USER is the
# honest default for anyone who runs the image by hand.
RUN adduser -D -u 65532 runner
USER runner

WORKDIR /workspace
