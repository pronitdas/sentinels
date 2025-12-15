import crypto from 'crypto';

export const SUPPORTED_SCANNERS = ['trivy', 'semgrep', 'bandit', 'clair', 'sonarqube'] as const;
export type SupportedScanner = (typeof SUPPORTED_SCANNERS)[number];

export interface UnifiedFinding {
  scanner_name: string;
  scanner_version?: string;
  rule_id: string;
  fingerprint: string;
  severity: string;
  file_path: string;
  start_line?: number;
  end_line?: number;
  title: string;
  description?: string;
  remediation?: string;
  cwe_ids?: string[];
  cve_ids?: string[];
  raw_data?: any;
}

function createFingerprint(parts: (string | number | undefined)[]) {
  const normalized = parts.filter(Boolean).join('|');
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

function normalizeSeverity(value: string | undefined) {
  return (value || 'UNKNOWN').toUpperCase();
}

export const parsers: Record<SupportedScanner, (output: any) => UnifiedFinding[]> = {
  trivy: (trivyOutput: any): UnifiedFinding[] => {
    const findings: UnifiedFinding[] = [];
    if (trivyOutput && Array.isArray(trivyOutput.Results)) {
      trivyOutput.Results.forEach((result: any) => {
        if (Array.isArray(result.Vulnerabilities)) {
          result.Vulnerabilities.forEach((vulnerability: any) => {
            const filePath = result.Target || vulnerability.Target || 'unknown-target';
            const ruleId = vulnerability.VulnerabilityID || vulnerability.ID || 'unknown-trivy-rule';
            const fingerprint = createFingerprint([
              filePath,
              ruleId,
              vulnerability.PkgName,
              vulnerability.InstalledVersion,
            ]);

            findings.push({
              scanner_name: 'trivy',
              scanner_version: trivyOutput.Metadata?.TrivyVersion,
              rule_id: ruleId,
              fingerprint,
              severity: normalizeSeverity(vulnerability.Severity),
              file_path: filePath,
              title: vulnerability.Title || vulnerability.VulnerabilityID || 'Trivy finding',
              description: vulnerability.Description,
              remediation: vulnerability.PrimaryURL ? `Refer to ${vulnerability.PrimaryURL}` : undefined,
              cve_ids: vulnerability.VulnerabilityID ? [vulnerability.VulnerabilityID] : undefined,
              raw_data: vulnerability,
            });
          });
        }
      });
    }
    return findings;
  },

  semgrep: (semgrepOutput: any): UnifiedFinding[] => {
    const findings: UnifiedFinding[] = [];
    if (semgrepOutput && Array.isArray(semgrepOutput.results)) {
      semgrepOutput.results.forEach((result: any) => {
        const filePath = result.path;
        const ruleId = result.check_id;
        const startLine = result.start?.line;
        const endLine = result.end?.line;
        const codeSnippet = result.extra?.lines || '';
        const fingerprint = createFingerprint([filePath, ruleId, startLine, endLine, codeSnippet]);

        findings.push({
          scanner_name: 'semgrep',
          scanner_version: semgrepOutput.version,
          rule_id: ruleId,
          fingerprint,
          severity: normalizeSeverity(result.extra?.severity),
          file_path: filePath,
          start_line: startLine,
          end_line: endLine,
          title: result.extra?.message || ruleId,
          description: result.extra?.metadata?.description || undefined,
          remediation: result.extra?.fix_regex ? `Consider fix: ${result.extra.fix_regex}` : undefined,
          cwe_ids: Array.isArray(result.extra?.metadata?.cwe)
            ? result.extra.metadata.cwe.map((c: any) => c.cwe_id)
            : undefined,
          cve_ids: Array.isArray(result.extra?.metadata?.cve) ? result.extra.metadata.cve : undefined,
          raw_data: result,
        });
      });
    }
    return findings;
  },

  bandit: (banditOutput: any): UnifiedFinding[] => {
    const findings: UnifiedFinding[] = [];
    if (banditOutput && Array.isArray(banditOutput.results)) {
      banditOutput.results.forEach((result: any) => {
        const filePath = result.filename;
        const ruleId = result.test_id || 'bandit-rule';
        const fingerprint = createFingerprint([filePath, ruleId, result.line_number]);

        findings.push({
          scanner_name: 'bandit',
          scanner_version: banditOutput.meta?.bandit_version,
          rule_id: ruleId,
          fingerprint,
          severity: normalizeSeverity(result.issue_severity),
          file_path: filePath,
          start_line: result.line_number,
          end_line: result.line_number,
          title: result.issue_text || ruleId,
          description: `${result.test_name || ''} (${result.issue_confidence || 'unknown'} confidence)`,
          remediation: result.more_info,
          cwe_ids: result.issue_cwe?.id ? [`CWE-${result.issue_cwe.id}`] : undefined,
          raw_data: result,
        });
      });
    }
    return findings;
  },

  clair: (clairOutput: any): UnifiedFinding[] => {
    const findings: UnifiedFinding[] = [];
    const vulnerabilities =
      clairOutput?.Vulnerabilities || clairOutput?.vulnerabilities || clairOutput || [];

    if (Array.isArray(vulnerabilities)) {
      vulnerabilities.forEach((vuln: any) => {
        const ruleId = vuln.Name || vuln.Vulnerability || vuln.id || 'clair-vuln';
        const filePath = clairOutput?.ImageName || vuln.LayerName || 'container-image';
        const fingerprint = createFingerprint([filePath, ruleId, vuln.FeatureName, vuln.FeatureVersion]);

        findings.push({
          scanner_name: 'clair',
          scanner_version: clairOutput?.ScannerVersion || clairOutput?.Version,
          rule_id: ruleId,
          fingerprint,
          severity: normalizeSeverity(vuln.Severity),
          file_path: filePath,
          title: vuln.Description || ruleId,
          description: vuln.Impact || vuln.Description,
          remediation: vuln.FixedBy ? `Update ${vuln.FeatureName} to ${vuln.FixedBy}` : undefined,
          cve_ids: vuln.Metadata?.NVD?.CVE || (vuln.CVE ? [vuln.CVE] : undefined),
          raw_data: vuln,
        });
      });
    }

    return findings;
  },

  sonarqube: (sonarOutput: any): UnifiedFinding[] => {
    const findings: UnifiedFinding[] = [];
    const issues = Array.isArray(sonarOutput?.issues) ? sonarOutput.issues : [];
    issues.forEach((issue: any) => {
      const component = issue.component || 'unknown-component';
      const filePath = component.includes(':') ? component.split(':').slice(1).join(':') : component;
      const ruleId = issue.rule || 'sonarqube-rule';
      const startLine = issue.textRange?.startLine;
      const endLine = issue.textRange?.endLine ?? startLine;
      const fingerprint = createFingerprint([issue.key, filePath, ruleId, startLine]);
      const remediation =
        typeof issue.ruleDescriptionContext === 'string'
          ? issue.ruleDescriptionContext
          : issue.type
          ? `Resolve ${issue.type.toLowerCase()} via SonarQube`
          : undefined;

      findings.push({
        scanner_name: 'sonarqube',
        scanner_version: sonarOutput?.serverVersion,
        rule_id: ruleId,
        fingerprint,
        severity: normalizeSeverity(issue.severity),
        file_path: filePath,
        start_line: startLine,
        end_line: endLine,
        title: issue.message || ruleId,
        description: issue.type ? `${issue.type} (${issue.status || 'OPEN'})` : undefined,
        remediation,
        raw_data: issue,
      });
    });
    return findings;
  },
};
