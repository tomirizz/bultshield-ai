import { useEffect, useState } from 'react';
import { request } from './api';
type History = { score_policy: string; comparison_policy: string; items: { scan_id: string; repository_id: string; branch: string; commit_sha: string; security_score: number; total: number; comparison: { new: number; fixed: number; unchanged: number } | null }[] };
export function SecurityHistory({ projectId }: { projectId: string }) {
  const [data, setData] = useState<History>(); const [error, setError] = useState('');
  useEffect(() => { let live = true; let timer: number; const load = async () => { try { const result = await request<History>(`/api/projects/${projectId}/security-history`); if (live) { setData(result); setError(''); } } catch (e) { if (live) setError(e instanceof Error ? e.message : 'Ошибка загрузки'); } if (live) timer = window.setTimeout(load, 5000); }; void load(); return () => { live = false; clearTimeout(timer); }; }, [projectId]);
  return <section className="panel"><div className="panel-heading"><h2>Security History</h2></div>{error && <p role="alert">{error}</p>}{data && <><p className="summary-note">{data.score_policy}</p><p className="summary-note">{data.comparison_policy}</p>{data.items.slice(-10).reverse().map(item => <div className="risk-review-item" key={item.scan_id}><a href={`#/findings?scan_id=${item.scan_id}`}>{item.branch} · {item.commit_sha?.slice(0, 7)}</a><p>Security Score: <strong>{item.security_score}/100</strong> · {item.total} находок</p><p>{item.comparison ? `New: ${item.comparison.new} · Fixed: ${item.comparison.fixed} · Unchanged: ${item.comparison.unchanged}` : 'Начальная точка: сопоставимой предыдущей проверки нет.'}</p></div>)}</>}</section>;
}
export function ContinuousControl({ repositoryId, enabled }: { repositoryId: string; enabled: boolean }) {
  const [value, setValue] = useState(enabled); const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  async function toggle() { setBusy(true); setError(''); try { await request(`/api/repositories/${repositoryId}/continuous`, { method: 'POST', body: JSON.stringify({ enabled: !value }) }); setValue(!value); } catch (e) { setError(e instanceof Error ? e.message : 'Ошибка'); } finally { setBusy(false); } }
  return <span><button className="text-button" disabled={busy} onClick={toggle}>{value ? 'Автопроверка: вкл. (5 мин)' : 'Включить автопроверку'}</button>{error && <span role="alert">{error}</span>}</span>;
}
