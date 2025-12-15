# Use an official Bun image as the base image
FROM oven/bun

# Set the working directory
WORKDIR /app

# Copy package.json and bun.lockb
COPY package.json bun.lock ./

# Install dependencies
RUN bun install --frozen-lockfile

# Copy the rest of the application code
COPY . .

# Build the Next.js application (if applicable)
RUN bun run build

# Expose the port the app runs on
EXPOSE 3000

# Start the application
CMD ["bun", "run", "start"]
