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

# Then take the distribution's security patches, because the pin alone would ship known-vulnerable
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
RUN apk upgrade --no-cache

LABEL fly_launch_runtime="Bun"

# Bun app lives here
WORKDIR /app

# Set production environment
ENV NODE_ENV="production"


# Throw-away build stage to reduce size of final image
FROM base AS build

# Install node modules
COPY bun.lock package.json ./
RUN bun install --frozen-lockfile

# Copy application code
COPY . .

# Build application
RUN bun run build

# Remove development dependencies. `--ci` is not a bun flag — bun ignores it silently and exits 0,
# so the previous form reinstalled devDependencies and pruned nothing. Verified safe: nothing under
# lib/ or database/ imports a devDependency, so the server and the db:setup release command both run
# on the production set alone.
RUN rm -rf node_modules && \
    bun install --production --frozen-lockfile


# Final stage for app image
FROM base

# Copy built application
COPY --from=build /app /app

# Start the server by default, this can be overwritten at runtime
EXPOSE 3000
CMD [ "bun", "start" ]
