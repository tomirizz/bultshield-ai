import { useEffect, useState } from 'react';
import { request } from './api';
import type { Finding } from './api';

type Review = { total: number; important: number; immediate: number; notice: string; issues: { finding: Finding; risk: { score: number; priority: string; reasons: { factor: string; points: number; explanation: string }[] } }[] };
export function SecurityReview({ projectId }: { projectId: string }) {
  const [data, setData] = useState<Review>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let live = true;
    void request<Review>(`/api/projects/${projectId}/security-review`).then(d => { if (live) setData(d); }).catch(e => { if (live) setError(String(e.message)); });
    return () => { live = false; };
  }, [projectId]);
  async function refresh() {
    setBusy(true); setError('');
    try { await request(`/api/projects/${projectId}/prioritize`, { method: 'POST' }); setData(await request(`/api/projects/${projectId}/security-review`)); }
    catch (e) { setError(e instanceof Error ? e.message : 'Ошибка обновления'); }
    finally { setBusy(false); }
  }
  return <section className="panel"><div className="panel-heading"><div><h2>Security Review</h2><p>Что исправить в первую очередь</p></div><button className="button secondary" disabled={busy} onClick={refresh}>{busy ? 'Обновляем…' : 'Обновить приоритеты'}</button></div>
    {error && <p className="alert error">{error}</p>}
    {data ? <><p>{data.total} находок · {data.important} с высоким приоритетом · {data.immediate} требуют первоочередного рассмотрения</p><p className="summary-note">{data.notice}</p>
      {data.issues.map(({ finding: f, risk }) => <article className="risk-review-item" key={f.id}><div><strong>{risk.priority} · {risk.score}/100</strong><a href={`#/findings/${f.id}`}>{f.title}</a></div><p>{f.scanner} · Scanner severity: {f.original_severity || f.severity} · {f.file || '—'}</p><details><summary>Почему такой приоритет</summary><ul>{risk.reasons.map(r => <li key={r.factor}>{r.explanation} (+{r.points})</li>)}</ul></details><a className="text-button" href={`#/findings/${f.id}`}>Разобрать находку и исправление →</a></article>)}
      {!data.total && <p className="detail-empty">Нет результатов успешных проверок для оценки.</p>}</> : !error && <p>Загрузка…</p>}
  </section>;
}
