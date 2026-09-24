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
}
export interface Finding {
  id: string; project_id: string; scanner: string; category: string; title: string;
  severity: string; status: string; file: string | null; line_start: number | null; created_at: string;
}
export interface NewProject {
  name: string; description: string; target_url: string | null;
  repository: { url: string; default_branch: string } | null;
}

export async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...options, headers: { 'Content-Type': 'application/json', ...options?.headers } });
  const data = await response.json();
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
  overview: () => request<Overview>('/api/overview'),
  readiness: () => request<Readiness>('/health/ready'),
  projects: () => request<Project[]>('/api/projects'),
  scans: () => request<Scan[]>('/api/scans'),
  findings: () => request<Finding[]>('/api/findings'),
  createProject: (data: NewProject) => request<Project>('/api/projects', { method: 'POST', body: JSON.stringify(data) }),
  addRepository: (id: string, url: string, default_branch: string) => request<Repository>(`/api/projects/${id}/repositories`, { method: 'POST', body: JSON.stringify({ url, default_branch }) }),
};
