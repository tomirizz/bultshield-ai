export interface Repository {
  id: string; project_id: string; url: string; default_branch: string; created_at: string;
}
export interface Project {
  id: string; name: string; description: string; target_url: string | null;
  created_at: string; updated_at: string; repositories: Repository[]; scan_count: number; finding_count: number;
}
export interface Overview {
  projects: number; repositories: number; scans: number; findings: number; stage: number;
  capabilities: { scanners: boolean; ai: boolean; rescans: boolean };
}
export interface Readiness {
  status: string; database: string; schema_revision: string; environment: string; stage: number;
}
export interface Scan {
  id: string; project_id: string; repository_id: string; status: string; created_at: string; commit_sha: string | null;
  started_at: string | null; completed_at: string | null;
  error_message: string | null; current_step: string | null; error_code: string | null;
  scanner_results: Record<string, { finding_count?: number; status: string; error?: string; scanned_files?: number; input_files?: number; db_updated_at?: string }>;
}
export interface Finding {
  id: string; project_id: string; scan_id: string; description: string; evidence: string; rule_id: string; scanner: string; category: string; title: string;
  cve: string | null; metadata: { package?: string; installed_version?: string; fixed_version?: string | null; suppressed?: boolean };
  cwe: string | null; original_severity: string | null; severity: string; status: string; file: string | null; line_start: number | null; line_end: number | null; created_at: string;
}
export interface NewProject {
  name: string; description: string; target_url: string | null;
  repository: { url: string; default_branch: string } | null;
}

export async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...options, headers: { 'Content-Type': 'application/json', ...options?.headers } });
  const data = await response.json().catch(() => { throw new Error('Сервис вернул некорректный ответ. Повторите позже.'); });
  if (data === null && response.ok) return data as T;
  if (!data) throw new Error(`Сервис временно недоступен (HTTP ${response.status}). Повторите позже.`);
  if (!response.ok) {
    const detail = data.detail;
    const message = typeof detail === 'string' ? detail : Array.isArray(detail)
      ? detail.map((item: { msg: string }) => item.msg.replace('Value error, ', '')).join('. ')
      : detail?.message || 'Не удалось выполнить запрос. Проверьте соединение.';
    throw new Error(message);
  }
  return data as T;
}

export const api = {
  startScan: (repositoryId: string) =>
    request<Scan>('/api/scans', {
      method: 'POST',
      body: JSON.stringify({ repository_id: repositoryId }),
    }),
  overview: () => request<Overview>('/api/overview'),
  readiness: () => request<Readiness>('/health/ready'),
  projects: () => request<Project[]>('/api/projects'),
  scans: () => request<Scan[]>('/api/scans'),
  findings: (filters: Record<string, string> = {}) => {
    const params = new URLSearchParams(Object.entries(filters).filter(([, value]) => value && value !== 'ALL'));
    return request<Finding[]>(`/api/findings?${params}`);
  },
  createProject: (data: NewProject) => request<Project>('/api/projects', { method: 'POST', body: JSON.stringify(data) }),
  addRepository: (id: string, url: string, default_branch: string) => request<Repository>(`/api/projects/${id}/repositories`, { method: 'POST', body: JSON.stringify({ url, default_branch }) }),
};
