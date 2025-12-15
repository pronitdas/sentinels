'use client';

import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { 
  ArrowLeft, Play, Clock, AlertTriangle, CheckCircle, XCircle, 
  FileCode, Terminal, Loader2 
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface PageProps {
  params: { id: string };
}

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

interface ScanRun {
  id: string;
  scanner_name: string;
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed';
  findings_count: number;
  started_at: string | null;
  completed_at: string | null;
  error_log?: string | null;
  created_at: string;
}

interface Scan {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  scanners: string[];
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  runs: ScanRun[];
  error_log?: string;
}

interface Finding {
  id: string;
  scanner_name: string;
  rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'UNKNOWN';
  file_path: string;
  start_line: number;
  title: string;
  description: string;
}

export default function ProjectDetails({ params }: PageProps) {
  const [project, setProject] = useState<any>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [selectedScanners, setSelectedScanners] = useState<string[]>(['trivy', 'semgrep']);

  const formatTimestamp = (value?: string | null) =>
    value ? new Date(value).toLocaleString() : '—';

  const statusTone = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-emerald-50 text-emerald-700 border border-emerald-100';
      case 'failed':
        return 'bg-rose-50 text-rose-700 border border-rose-100';
      case 'running':
      case 'queued':
        return 'bg-amber-50 text-amber-700 border border-amber-100';
      default:
        return 'bg-slate-50 text-slate-700 border border-slate-100';
    }
  };

  const AVAILABLE_SCANNERS = [
    { id: 'trivy', label: 'Trivy' },
    { id: 'semgrep', label: 'Semgrep' },
    { id: 'bandit', label: 'Bandit' },
    { id: 'clair', label: 'Clair' },
    { id: 'sonarqube', label: 'SonarQube' },
  ];

  const toggleScanner = (id: string) => {
    setSelectedScanners(prev => 
      prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]
    );
  };

  const fetchProjectData = useCallback(async () => {
    try {
      // 1. Fetch Project Details (This endpoint wasn't explicitly created in list, but assuming we can filter or reuse list for now. 
      // Actually the API only has list all. Let's just fetch all and find one for prototype speed, or assume we add get-one later.)
      // For now, I'll fetch all and filter.
      const res = await fetch(`${API_URL}/projects`);
      const projects = await res.json();
      const current = projects.find((p: any) => p.id === params.id);
      setProject(current);

      // 2. Fetch Scans (Ideally filtered by project, but our API is simple. We need to add query params or filter client side)
      // The API currently has /scans/:id for single scan. We need list by project.
      // I'll skip listing *all* scans for now and just focus on the active/latest one if we had a proper endpoint.
      // Wait, the design doc had /scans/:id. 
      // Let's implement a poller for the active scan if we trigger one.
      
      const scansRes = await fetch(`${API_URL}/projects/${params.id}/scans`);
      const history = await scansRes.json();
      setScans(history);

      // For findings, we have /findings?severity=...
      // We really need /findings?projectId=... or /scans/:id/findings. 
      // I'll assume for this prototype we fetch global findings and filter client side (Not performant but works for demo).
      const findingsRes = await fetch(`${API_URL}/findings`);
      const allFindings = await findingsRes.json();
      // We can't easily filter findings by project without a join in backend.
      // Let's blindly show all findings for now, or just findings from the *scans* we know belong to this project.
      // Actually, let's just show all findings as a "Global View" for this MVP if project specific is hard.
      // BUT, let's try to be better. The findings table has scan_id. 
      // So if we track scan IDs we can filter findings.
      setFindings(allFindings.filter((f: any) => f.scan_id === activeScanId)); 
      
    } catch (e) {
      console.error(e);
    }
  }, [params.id, activeScanId]);

  useEffect(() => {
    fetchProjectData();
  }, [fetchProjectData]);

  // Polling for scan status
  useEffect(() => {
    if (!activeScanId) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API_URL}/scans/${activeScanId}`);
        if (res.ok) {
          const scan = await res.json();
          if (scan.status === 'completed' || scan.status === 'failed') {
            setIsScanning(false);
            // Fetch findings for this scan
            const fRes = await fetch(`${API_URL}/findings`); // Inefficient, but stick to plan
            const allF = await fRes.json();
            setFindings(allF.filter((f: any) => f.scan_id === activeScanId));
            clearInterval(interval);
          }
        }
      } catch (e) {
        console.error("Polling error", e);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [activeScanId]);

  const triggerScan = async () => {
    if (selectedScanners.length === 0) {
      alert("Please select at least one scanner.");
      return;
    }
    setIsScanning(true);
    try {
      const res = await fetch(`${API_URL}/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: params.id,
          scanners: selectedScanners
        }),
      });
      const data = await res.json();
      setActiveScanId(data.id);
    } catch (e) {
      console.error(e);
      setIsScanning(false);
    }
  };

  if (!project) return <div className="p-10">Loading project...</div>;

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans">
      <header className="bg-white border-b border-slate-200 px-8 py-4 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link href="/" className="p-2 hover:bg-slate-100 rounded-full transition-colors">
              <ArrowLeft className="w-5 h-5 text-slate-500" />
            </Link>
            <div>
              <h1 className="text-xl font-bold text-slate-900">{project.name}</h1>
              <p className="text-xs text-slate-500 font-mono">{project.path}</p>
            </div>
          </div>
          
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-3 bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-100">
              {AVAILABLE_SCANNERS.map(scanner => (
                <label key={scanner.id} className="flex items-center gap-1.5 text-xs font-medium text-slate-600 cursor-pointer hover:text-indigo-600 transition-colors select-none">
                  <input 
                    type="checkbox" 
                    checked={selectedScanners.includes(scanner.id)}
                    onChange={() => toggleScanner(scanner.id)}
                    disabled={isScanning}
                    className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 w-3.5 h-3.5"
                  />
                  {scanner.label}
                </label>
              ))}
            </div>

            <button
              onClick={triggerScan}
              disabled={isScanning}
              className={cn(
                "flex items-center gap-2 px-4 py-2 rounded-md font-medium transition-all",
                isScanning 
                  ? "bg-slate-100 text-slate-400 cursor-not-allowed"
                  : "bg-indigo-600 text-white hover:bg-indigo-700 shadow-sm"
              )}
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Run Analysis
                </>
              )}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto p-8">
        {/* Status Area */}
        {activeScanId && (
           <div className="mb-8 p-4 bg-white border border-indigo-100 rounded-lg shadow-sm flex items-center gap-3">
             <Terminal className="w-5 h-5 text-indigo-500" />
             <div className="flex-1">
               <p className="text-sm font-medium text-slate-900">
                 Scan ID: <span className="font-mono text-xs text-slate-500">{activeScanId}</span>
               </p>
               <p className="text-xs text-slate-500">
                 {isScanning ? 'Orchestrating scanners...' : 'Scan finished.'}
               </p>
             </div>
           </div>
        )}

        {/* Scan History */}
        <section className="mb-10">
          <h2 className="text-lg font-bold text-slate-800 flex items-center gap-2 mb-3">
            <Clock className="w-5 h-5 text-slate-500" />
            Scan History
            <span className="bg-slate-200 text-slate-600 text-xs px-2 py-0.5 rounded-full">{scans.length}</span>
          </h2>
          {scans.length === 0 ? (
            <div className="bg-white border border-dashed border-slate-200 rounded-xl p-6 text-sm text-slate-500">
              No scans recorded yet. Launch your first analysis to populate history.
            </div>
          ) : (
            <div className="space-y-4">
              {scans.map((scan) => (
                <div key={scan.id} className="bg-white rounded-xl border border-slate-200 p-4 shadow-sm">
                  <div className="flex items-center justify-between flex-wrap gap-3">
                    <div>
                      <p className="text-xs font-mono text-slate-400">Scan ID</p>
                      <p className="text-sm font-semibold text-slate-900">{scan.id}</p>
                    </div>
                    <div className={cn('text-xs px-3 py-1 rounded-full font-semibold', statusTone(scan.status))}>
                      {scan.status.toUpperCase()}
                    </div>
                    <div className="text-xs text-slate-500">
                      Started: {formatTimestamp(scan.started_at || scan.created_at)} · Completed:{' '}
                      {formatTimestamp(scan.completed_at)}
                    </div>
                  </div>
                  <div className="mt-4 space-y-2">
                    {scan.runs.length === 0 ? (
                      <p className="text-xs text-slate-500">No individual scanner data recorded.</p>
                    ) : (
                      scan.runs.map((run) => (
                        <div
                          key={run.id}
                          className="flex items-center justify-between gap-3 text-xs px-3 py-2 bg-slate-50 rounded-lg border border-slate-100"
                        >
                          <div className="flex items-center gap-2">
                            <span className="font-semibold text-slate-700">{run.scanner_name}</span>
                            <span className={cn('px-2 py-0.5 rounded-full font-semibold', statusTone(run.status))}>
                              {run.status.toUpperCase()}
                            </span>
                          </div>
                          <div className="text-slate-500">
                            Findings: <span className="font-semibold text-slate-700">{run.findings_count ?? 0}</span>
                          </div>
                          <div className="text-slate-400">
                            {formatTimestamp(run.started_at)} → {formatTimestamp(run.completed_at)}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Findings List */}
        <div className="space-y-4">
          <h2 className="text-lg font-bold text-slate-800 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-500" />
            Security Findings
            <span className="bg-slate-200 text-slate-600 text-xs px-2 py-0.5 rounded-full">
              {findings.length}
            </span>
          </h2>

          {findings.length === 0 ? (
            <div className="text-center py-16 bg-white rounded-xl border border-dashed border-slate-200">
              <CheckCircle className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
              <p className="text-slate-500">No findings to display yet.</p>
              <p className="text-xs text-slate-400">Run a scan to detect vulnerabilities.</p>
            </div>
          ) : (
            <div className="grid gap-3">
              {findings.map((f) => (
                <div key={f.id} className="p-4 bg-white rounded-lg border border-slate-200 shadow-sm hover:shadow-md transition-shadow">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={cn(
                          "px-2 py-0.5 text-[10px] font-bold tracking-wider uppercase rounded-sm",
                          f.severity === 'CRITICAL' ? "bg-red-100 text-red-700" :
                          f.severity === 'HIGH' ? "bg-orange-100 text-orange-700" :
                          f.severity === 'MEDIUM' ? "bg-yellow-100 text-yellow-700" :
                          "bg-blue-100 text-blue-700"
                        )}>
                          {f.severity}
                        </span>
                        <span className="text-xs font-mono text-slate-400">{f.scanner_name}</span>
                      </div>
                      <h3 className="font-semibold text-slate-900">{f.title}</h3>
                      <p className="text-sm text-slate-600 mt-1 line-clamp-2">{f.description}</p>
                      
                      <div className="mt-3 flex items-center gap-2 text-xs text-slate-500 font-mono bg-slate-50 p-1.5 rounded w-fit">
                        <FileCode className="w-3 h-3" />
                        {f.file_path}:{f.start_line}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
