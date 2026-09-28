import { useState } from 'react';
import { request } from './api';
type Repo = { name: string; url: string; branch: string };
export function GitHubPicker({ onChoose }: { onChoose: (repo: Repo) => void }) {
  const [items, setItems] = useState<Repo[]>([]); const [error, setError] = useState(''); const [busy, setBusy] = useState(false); const [page, setPage] = useState(1); const [more, setMore] = useState(false);
  async function load(next = 1) { setBusy(true); setError(''); try { const data = await request<{ items: Repo[]; has_more: boolean }>(`/api/github/repositories?page=${next}`); setItems(data.items); setPage(next); setMore(data.has_more); } catch (e) { setError(e instanceof Error ? e.message : 'Ошибка GitHub'); } finally { setBusy(false); } }
  return <div><button className="button secondary" type="button" disabled={busy} onClick={() => load()}>Выбрать из GitHub</button>{error && <p role="alert">{error}</p>}{items.length > 0 && <label>Репозиторий<select defaultValue="" onChange={e => { const repo = items.find(r => r.url === e.target.value); if (repo) onChoose(repo); }}><option value="" disabled>Выберите репозиторий</option>{items.map(r => <option key={r.url} value={r.url}>{r.name}</option>)}</select></label>}{page > 1 && <button type="button" disabled={busy} onClick={() => load(page - 1)}>Назад</button>}{more && <button type="button" disabled={busy} onClick={() => load(page + 1)}>Следующие</button>}</div>;
}
