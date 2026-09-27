import { useEffect, useState } from 'react';
import { request } from './api';

type Target = { id: string; url: string; allowed: boolean };
type Data = { items: Target[]; allowlist: string[]; rate_per_second: number; templates: string[] };
export function WebTargets({ projectId }: { projectId: string }) {
  const [data, setData] = useState<Data | null>(null);
  const [url, setUrl] = useState('');
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  useEffect(() => { let live = true; request<Data>(`/api/projects/${projectId}/targets`).then(d => { if (live) setData(d); }).catch(e => { if (live) setError(e.message); }); return () => { live = false; }; }, [projectId]);
  async function add(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    try { await request(`/api/projects/${projectId}/targets`, { method: 'POST', body: JSON.stringify({ url, confirmed_control: consent }) }); setData(await request<Data>(`/api/projects/${projectId}/targets`)); setUrl(''); setConsent(false); }
    catch (e) { setError(e instanceof Error ? e.message : 'Не удалось добавить адрес'); }
    finally { setBusy(false); }
  }
  async function scan(id: string) {
    setBusy(true); setError(''); setMessage('');
    try { await request(`/api/targets/${id}/scan`, { method: 'POST' }); setMessage('Проверка поставлена в очередь. Статус появится в истории, результаты — в находках Nuclei.'); }
    catch (e) { setError(e instanceof Error ? e.message : 'Не удалось запустить'); }
    finally { setBusy(false); }
  }
  return <section className="panel ai-explanation"><div className="panel-heading"><div><h2>Test / Staging · Nuclei</h2><p>Ограниченная проверка HTTP-заголовков</p></div></div><div className="ai-content">
    <p>Три локальных шаблона, один запрос в секунду. Только разрешённые HTTPS-адреса, без перенаправлений. Эксплуатация уязвимостей и перебор не выполняются.</p>
    {error && <p className="alert error" role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    {data && !data.allowlist.length && <p>Оператору нужно добавить test/staging origin в NUCLEI_ALLOWED_TARGETS у приложения и worker на Bult.ai. До этого сетевые проверки недоступны.</p>}
    {!!data?.allowlist.length && <form onSubmit={e => void add(e)} className="target-form"><label>Разрешённый адрес<select value={url} onChange={e => setUrl(e.target.value)} required><option value="">Выберите staging</option>{data.allowlist.map(v => <option key={v} value={v}>{v}</option>)}</select></label><label className="fix-consent"><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} />Я владею сервисом или имею разрешение на его проверку.</label><button className="button secondary" disabled={busy || !consent || !url}>Добавить адрес</button></form>}
    {data?.items.map(t => <div className="repository-row" key={t.id}><span>{t.url}</span><button className="button secondary" disabled={busy || !t.allowed} onClick={() => void scan(t.id)}>{t.allowed ? 'Проверить Nuclei' : 'Исключён из allowlist'}</button></div>)}
  </div></section>;
}
