const DEFAULT_IGNORE_PATTERNS = [
  // Geospatial data
  '*.tiff', '*.tif', '*.geojson', '*.pmtiles', '*.gpkg', '*.shp', '*.kml', '*.kmz',
  // Binary/compiled
  '*.pyc', '*.pyo', '*.so', '*.dll', '*.exe', '*.o', '*.a', '*.dylib', '*.wasm',
  // Compressed
  '*.gz', '*.zip', '*.tar', '*.bz2', '*.xz', '*.7z', '*.rar',
  // Images
  '*.png', '*.jpg', '*.jpeg', '*.gif', '*.bmp', '*.ico', '*.webp', '*.svg',
  // Data files
  '*.csv', '*.parquet', '*.mat', '*.sav', '*.pkl', '*.pickle', '*.npy', '*.npz',
  '*.h5', '*.hdf5', '*.nc', '*.zarr',
  // Fonts
  '*.woff', '*.woff2', '*.ttf', '*.otf', '*.eot',
  // Documents
  '*.pdf', '*.doc', '*.docx', '*.xls', '*.xlsx',
  // Build artifacts
  '*.map',
  // Directories (as patterns)
  'node_modules', '__pycache__', '.git', 'dist', 'build', '.venv', 'venv',
  '*.egg-info', '.eggs', '.tox', '.pytest_cache', '.mypy_cache',
  // Lock files (can be large)
  'pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'poetry.lock', 'Pipfile.lock',
];

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
