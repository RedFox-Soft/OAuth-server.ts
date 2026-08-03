# syntax = docker/dockerfile:1

FROM oven/bun:alpine AS base

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
