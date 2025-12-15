const DEFAULT_IGNORE_PATTERNS = ['*.tiff', '*.geojson', '*.pmtiles'];

function parseEnvIgnorePatterns() {
  const raw = process.env.SENTINEL_IGNORE_PATTERNS;
  if (!raw) return [];
  return raw
    .split(',')
    .map((pattern) => pattern.trim())
    .filter(Boolean);
}

function expandPatterns(patterns: string[]) {
  const normalized = new Set<string>();
  patterns.forEach((pattern) => {
    normalized.add(pattern);
    if (!pattern.startsWith('**/')) {
      normalized.add(`**/${pattern}`);
    }
  });
  return Array.from(normalized);
}

export const COMMON_IGNORE_PATTERNS = expandPatterns([
  ...DEFAULT_IGNORE_PATTERNS,
  ...parseEnvIgnorePatterns(),
]);

export function hasIgnorePatterns() {
  return COMMON_IGNORE_PATTERNS.length > 0;
}

// Path mapping: transforms host paths to container paths
// HOST_PATH_PREFIX: the prefix to strip from incoming paths (e.g., /home/pronit)
// CONTAINER_PATH_PREFIX: the prefix to add for container access (e.g., /workspace or empty)
export const HOST_PATH_PREFIX = process.env.HOST_PATH_PREFIX || '/home/pronit';
export const CONTAINER_PATH_PREFIX = process.env.CONTAINER_PATH_PREFIX || '/workspace';

export function toContainerPath(hostPath: string): string {
  if (hostPath.startsWith(HOST_PATH_PREFIX)) {
    return CONTAINER_PATH_PREFIX + hostPath.slice(HOST_PATH_PREFIX.length);
  }
  return hostPath;
}

export function toHostPath(containerPath: string): string {
  if (containerPath.startsWith(CONTAINER_PATH_PREFIX)) {
    return HOST_PATH_PREFIX + containerPath.slice(CONTAINER_PATH_PREFIX.length);
  }
  return containerPath;
}
