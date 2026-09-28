import { useEffect, useState } from 'react';
import { request } from './api';
import type { Finding } from './api';

type Review = { has_successful_scan: boolean; previous_results: boolean; total: number; important: number; immediate: number; notice: string; issues: { finding: Finding; risk: { score: number; priority: string; reasons: { factor: string; points: number; explanation: string }[] } }[] };
export function SecurityReview({ projectId }: { projectId: string }) {
  const [data, setData] = useState<Review>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let live = true; let timer: number;
    const load = async () => { try { const result = await request<Review>(`/api/projects/${projectId}/security-review`); if (live) { setData(result); setError(''); } } catch (e) { if (live) setError(e instanceof Error ? e.message : 'Ошибка загрузки'); } if (live) timer = window.setTimeout(load, 5000); };
    void load(); return () => { live = false; clearTimeout(timer); };
  }, [projectId]);
  async function refresh() {
    setBusy(true); setError('');
    try { await request(`/api/projects/${projectId}/prioritize`, { method: 'POST' }); setData(await request(`/api/projects/${projectId}/security-review`)); }
    catch (e) { setError(e instanceof Error ? e.message : 'Ошибка обновления'); }
    finally { setBusy(false); }
  }
  return <section className="panel review-panel"><div className="panel-heading"><div><h2>Приоритетные проблемы</h2><p>Что исправить в первую очередь</p></div><button className="button secondary" disabled={busy} onClick={refresh}>{busy ? 'Обновляем…' : 'Обновить приоритеты'}</button></div>
    {error && <p className="alert error">{error}</p>}
    {data ? <><div className="review-metrics"><div><strong>{data.total}</strong><span>Всего находок</span></div><div><strong>{data.important}</strong><span>Высокий приоритет</span></div><div><strong>{data.immediate}</strong><span>Требуют срочного внимания</span></div></div><p className="summary-note">Последние успешные проверки. {data.notice}</p>{data.previous_results && <p className="alert error">Последняя попытка завершилась ошибкой. Показаны предыдущие успешные результаты.</p>}
      {data.issues.map(({ finding: f, risk }) => <article className="risk-review-item" key={f.id}><div><strong>{risk.priority} · {risk.score}/100</strong><a href={`#/findings/${f.id}`}>{f.title}</a></div><p>{f.scanner} · Оценка сканера: {f.original_severity || f.severity} · {f.file || '—'}</p><details><summary>Почему такой приоритет</summary><ul>{risk.reasons.map(r => <li key={r.factor}>{r.explanation} (+{r.points})</li>)}</ul></details><a className="text-button" href={`#/findings/${f.id}`}>Подробнее и исправление →</a></article>)}
      {!data.total && <p className="detail-empty">{data.has_successful_scan ? 'В успешной проверке находок нет. Это не гарантирует безопасность приложения.' : 'Успешных проверок пока нет.'}</p>}</> : !error && <p>Загрузка…</p>}
  </section>;
}
