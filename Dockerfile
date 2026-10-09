# syntax = docker/dockerfile:1

# Pinned by digest, and to a *versioned* tag rather than the floating `alpine`, because of how the
# digest gets refreshed. Dependabot follows a change of tag version and carries the digest along with
# it; it has no mechanism for "same tag, newer digest" (dependabot-core#1971 is still an open feature
# request, and #4419 records that no pull request is opened when a digest alone identifies the image).
# So `alpine@sha256:...` would have frozen this at whatever was current the day it was written — the
# exact objection that kept it unpinned until now — while `1.4.2-alpine@sha256:...` is a reference
# Dependabot can actually move. The trade is that a Bun upgrade now arrives as a reviewable pull
# request instead of silently on the next build, which for the layer that carries OpenSSL is the
# direction worth having.
FROM oven/bun:1.4.2-alpine@sha256:d888c0ae6c86d7866ff10c5aafdd9077b36aee6455b33dd270fb93c0dd5cef6f AS base

# Bun app lives here
WORKDIR /app

# Set production environment
ENV NODE_ENV="production"


# The production dependencies, in a stage of their own that sees only the lockfile and the manifest.
# Installed after the build instead, they were reinstalled on every code change — the slowest step of
# a deploy, and a fresh layer to push each time for bytes that had not changed. Here the layer is
# rebuilt only when `bun.lock`, `package.json` or a dependency patch is. The lockfile names the patches,
# so an install without `patches/` fails even when the patched package is a dev dependency it skips.
FROM base AS deps

COPY bun.lock package.json ./
COPY patches ./patches
RUN bun install --production --frozen-lockfile


# Throw-away build stage to reduce size of final image
FROM base AS build

# Install node modules
COPY bun.lock package.json ./
COPY patches ./patches
RUN bun install --frozen-lockfile

# Copy application code
COPY . .

# Build application
RUN bun run build

# Drop the development dependencies; the final stage takes the production set from `deps`. Verified
# safe: nothing under lib/ or database/ imports a devDependency, so the server and the db:setup
# release command both run on the production set alone.
RUN rm -rf node_modules


# Final stage for app image
FROM base AS runtime

# Take the distribution's security patches, because the pin alone would ship known-vulnerable
# packages. The two clocks are not the same: CVE-2026-14456 was fixed in Alpine's libssl3 3.5.8-r0 and
# served from the v3.22 repository while this base image still carried 3.5.7-r0 — one OpenSSL, twenty
# image-scan alerts. Waiting for the base image to be rebuilt means deploying the vulnerable one until
# it is.
#
# This is in tension with the pin above and the tension is deliberate: the digest fixes what is
# inherited, and this line refuses to inherit the unpatched half of it. What is given up is
# build-to-build reproducibility over time — the same Dockerfile produces different packages as the
# repository moves — and that is the cheaper thing to give up, since a build pinned to a
# known-vulnerable package is reproducible in the way a photograph is. Within a single run the scan
# and the release still build identically, which is the property the pipeline actually depends on, and
# `bun.lock` still pins everything the application itself runs on.
#
# It runs here, in the stage that ships, and not in `base`, because a build cache serves this layer
# for as long as its line and the base image are unchanged: 0.8.0 shipped zlib 1.3.2-r0 for that
# reason after Alpine had published 1.3.2-r1 (CVE-2026-85091). Every workflow that builds an image —
# release, scan, and a conformance deploy from source — passes its run id as PACKAGES_AS_OF, and a new
# value is a cache miss on the line below, so each of those builds takes the repository as it is that
# day. A local build without the argument keeps the cache. Keeping the upgrade out of `base` is what
# lets `deps` and `build` stay cached meanwhile: they produce only files, which the OS packages they
# were built beside never reach.
ARG PACKAGES_AS_OF
RUN apk upgrade --no-cache

LABEL fly_launch_runtime="Bun"

# Copy built application, then the production dependencies
COPY --from=build /app /app
COPY --from=deps /app/node_modules /app/node_modules

# Start the server by default, this can be overwritten at runtime
EXPOSE 3000
CMD [ "bun", "start" ]
