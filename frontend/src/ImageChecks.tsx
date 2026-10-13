import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { request } from './api';
import type { Project, Scan } from './api';

type Configuration = { image_registries: string[]; rescan_hours: number; llm_provider: string; sandbox_note: string };
type Item = { id: string; title: string; severity: string; component: string; installed_version: string | null; fixed_version: string | null; scanner: string; status_text: string; status_reason: string | null; fix: { diff?: string; outcome?: string } | null };
type Report = {
  check: { id: string; status: string; error_message: string | null };
  subject: { commit_sha: string | null; image: string | null; image_digest: string | null; watched: boolean; trigger: string };
  verdict: { result: string; statement: string };
  facts: { total_findings: number };
  findings: { items: Item[]; total: number; limit: number; offset: number };
  assumptions: { call_id?: string; finding_id?: string; subject?: string; explanation: string; risk?: string; recommended_fix?: string }[];
  llm: { message: string; input_tokens: number; output_tokens: number; cost_usd: number; job: { status: string } | null; failures: { subject: string; message: string }[] };
};
const label: Record<string, string> = { QUEUED: 'В очереди', CLONING: 'Подготовка', SCANNING: 'Сканирование', ANALYSING: 'Обработка', COMPLETED: 'Завершено', FAILED: 'Ошибка', RUNNING: 'Выполняется' };

export function ImageChecks({ project }: { project: Project }) {
  const [configuration, setConfiguration] = useState<Configuration | null>(null);
  const [checks, setChecks] = useState<Scan[]>([]);
  const [selected, setSelected] = useState(() => new URLSearchParams(window.location.hash.split('?')[1] || '').get('check') || '');
  const [offset, setOffset] = useState(0);
  const [report, setReport] = useState<Report | null>(null);
  const [mode, setMode] = useState('image');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [loadError, setLoadError] = useState('');
  const [notice, setNotice] = useState('');
  useEffect(() => {
    let active = true; let timer: number;
    const poll = async () => {
      try {
        const [config, rows, result] = await Promise.all([
          request<Configuration>('/api/checks-configuration'),
          request<Scan[]>(`/api/scans?project_id=${project.id}&limit=100`),
          selected ? request<Report>(`/api/checks/${selected}/report?limit=50&offset=${offset}`) : Promise.resolve(null),
        ]);
        if (active) { setConfiguration(config); setChecks(rows.filter(s => s.kind !== 'verification' && s.kind !== 'web')); setReport(result); setLoadError(''); }
      } catch (e) { if (active) { setLoadError(e instanceof Error ? e.message : 'Отчёт недоступен'); setReport(null); } }
      if (active) timer = window.setTimeout(poll, 5000);
    };
    void poll(); return () => { active = false; window.clearTimeout(timer); };
  }, [project.id, selected, offset]);
  function choose(id: string) { setSelected(id); setOffset(0); setReport(null); setNotice(''); }
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); setBusy(true); setError(''); setNotice('');
    const data = new FormData(e.currentTarget);
    const subject = String(data.get('subject') || '').trim();
    try {
      const scan = await request<Scan>('/api/checks', { method: 'POST', body: JSON.stringify({ repository_id: data.get('repository'),
        ...(mode === 'image' ? { image: subject, watch: data.get('watch') === 'on' } : subject ? { commit: subject } : {}) }) });
      choose(scan.id); setNotice('Проверка поставлена в очередь. Результат появится здесь.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Не удалось запустить проверку'); }
    finally { setBusy(false); }
  }
  async function explain() {
    setBusy(true); setError('');
    try { await request(`/api/checks/${selected}/explanations`, { method: 'POST' }); setNotice('Пояснения запрошены у модели. Они появятся отдельно от фактов сканера.'); }
    catch (e) { setError(e instanceof Error ? e.message : 'Модель недоступна'); }
    finally { setBusy(false); }
  }
  return <section className="panel image-checks" aria-label="Проверки образов и зависимостей"><div className="panel-heading"><div><h2>Проверки образов и зависимостей</h2><p>Готовый Docker-образ или конкретная версия исходников</p></div></div>
    <form onSubmit={e => void submit(e)} className="check-form">
      <label>Что проверить<select value={mode} onChange={e => setMode(e.target.value)}><option value="image">Docker-образ</option><option value="source">Исходники и зависимости npm</option></select></label>
      <label>Репозиторий<select name="repository" required>{project.repositories.map(r => <option key={r.id} value={r.id}>{r.url.replace('https://github.com/', '')}</option>)}</select></label>
      <label>{mode === 'image' ? 'Адрес образа с тегом или digest' : 'Полный коммит (пусто — последняя версия ветки)'}<input key={mode} name="subject" required={mode === 'image'} maxLength={255} placeholder={mode === 'image' ? 'docker.io/owner/app:version' : '40 символов коммита'} /></label>
      {mode === 'image' && <><p className="form-help">Digest — точный идентификатор содержимого образа. Разрешённые реестры: {configuration?.image_registries.join(', ') || 'не настроены'}.</p><label className="check-toggle"><input type="checkbox" name="watch" disabled={!configuration?.rescan_hours} />Перепроверять опубликованный образ каждые {configuration?.rescan_hours || '—'} ч.</label></>}
      <button className="button primary" disabled={busy || !project.repositories.length || !configuration || (mode === 'image' && !configuration.image_registries.length)}>{busy ? 'Отправляем…' : 'Запустить проверку версии'}</button>
    </form>
    {error && <p role="alert" className="alert error">{error}</p>}{loadError && <p role="alert" className="alert error">{loadError}</p>}{notice && <p role="status">{notice}</p>}
    <label>Отчёт проверки<select value={selected} onChange={e => choose(e.target.value)}><option value="">Выберите проверку</option>{selected && !checks.some(s => s.id === selected) && <option value={selected}>{selected.slice(0, 8)}</option>}{checks.map(s => <option key={s.id} value={s.id}>{s.kind === 'image' ? 'Образ' : 'Исходники'} · {label[s.status] || s.status} · {s.id.slice(0, 8)}</option>)}</select></label>
    {selected && !report && !loadError && <p role="status">Загружаем отчёт…</p>}
    {report && <div className="check-report"><h3>{label[report.check.status] || report.check.status}</h3><p className={report.verdict.result === 'INCOMPLETE' ? 'alert error' : 'summary-note'}>{report.verdict.statement}</p>{report.check.error_message && <p className="form-error">{report.check.error_message}</p>}
      <dl className="finding-facts"><div><dt>Коммит исходников</dt><dd>{report.subject.commit_sha || 'Не подтверждён для этой проверки'}</dd></div><div><dt>Образ</dt><dd>{report.subject.image || 'Проверялись исходники'}</dd></div><div><dt>Digest образа</dt><dd>{report.subject.image_digest || 'Не измерен'}</dd></div><div><dt>Повторные проверки</dt><dd>{report.subject.watched ? 'Включены' : 'Не включены'}</dd></div></dl>
      <h3>Факты сканера · {report.facts.total_findings} находок</h3><div className="findings-table-wrap"><table className="findings-table"><thead><tr><th>Проблема</th><th>Компонент</th><th>Возможное исправление</th><th>Результат</th></tr></thead><tbody>{report.findings.items.map(f => <tr key={f.id}><td><span className={`severity severity-${f.severity.toLowerCase()}`}>{f.severity}</span><a href={`#/findings/${f.id}`}>{f.title}</a><small>Источник: {f.scanner}</small></td><td>{f.component}<small>{f.installed_version}</small></td><td>{f.fixed_version || 'Исправленная версия не указана'}</td><td>{f.status_text}{f.status_reason && <small>{f.status_reason}</small>}{f.fix?.diff && <details><summary>Изменения (diff)</summary><pre>{f.fix.diff}</pre><p>{f.fix.outcome}</p></details>}</td></tr>)}</tbody></table></div>
      <div className="pagination"><button className="button secondary" disabled={!offset} onClick={() => { setReport(null); setOffset(Math.max(0, offset - 50)); }}>← Назад</button><span>{offset + report.findings.items.length} из {report.findings.total}</span><button className="button secondary" disabled={offset + 50 >= report.findings.total} onClick={() => { setReport(null); setOffset(offset + 50); }}>Далее →</button></div>
      <h3>Пояснения модели · предположения</h3><p>{report.llm.message}</p><button className="button secondary" disabled={busy || report.check.status !== 'COMPLETED' || ['QUEUED', 'RUNNING'].includes(report.llm.job?.status || '')} onClick={() => void explain()}>Объяснить находки</button>
      {report.assumptions.map((a, i) => <article className="check-explanation" key={a.call_id || a.finding_id || i}><h4>{a.subject || 'Пояснение'}</h4><p>{a.explanation}</p>{a.risk && <p>{a.risk}</p>}{a.recommended_fix && <p>{a.recommended_fix}</p>}</article>)}
      {report.llm.failures.map((f, i) => <p className="form-error" key={i}>{f.subject}: {f.message}</p>)}
      <p className="form-help">Токены — единицы текста модели: вход {report.llm.input_tokens}, выход {report.llm.output_tokens}. Расчёт по настроенному тарифу: ${report.llm.cost_usd}. Стоимость размещения модели на Bult сюда не входит.</p>
      <p className="summary-note">Проверка исправления не означает, что оно применено в работающем приложении. Запущенную версию Bult этот отчёт пока не наблюдает.</p>
    </div>}
    {configuration && <p className="summary-note">{configuration.sandbox_note}</p>}
  </section>;
}
