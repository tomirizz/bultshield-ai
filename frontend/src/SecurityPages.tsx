import { useEffect, useState } from 'react';
import type { Finding, Project, Scan } from './api';
import { request } from './api';

export const labels: Record<string, string> = { OPEN: 'Открыта', AI_ANALYZED: 'Разобрана', FIX_PROPOSED: 'Предложено исправление', FIX_APPLIED: 'Исправление внесено', RECHECKING: 'Повторная проверка', VERIFIED_FIXED: 'Исправлена', STILL_DETECTED: 'Обнаружена повторно', QUEUED: 'В очереди', CLONING: 'Загрузка репозитория', SCANNING: 'Проверка', ANALYSING: 'Обработка результатов', NORMALIZING: 'Обработка результатов', AI_ANALYSIS: 'Обработка результатов', COMPLETED: 'Завершено', FAILED: 'Ошибка', RUNNING: 'Выполняется', PENDING: 'Ожидает запуска' };
const categories: Record<string, string> = { secret: 'Секреты', code: 'Код', dependency: 'Зависимости', configuration: 'Конфигурации', web: 'Веб' };
const scannerNames: Record<string, string> = { gitleaks: 'Gitleaks', semgrep: 'Semgrep', trivy: 'Trivy' };
const active = (s: Scan) => !['COMPLETED', 'FAILED'].includes(s.status);
const date = (v: string | null) => v ? new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(v)) : '—';
export function go(path: string, values: Record<string, string> = {}) { const query = new URLSearchParams(Object.entries(values).filter(([, v]) => v)); window.location.hash = `/${path}${query.size ? '?' + query : ''}`; }
export function readRoute() { const [path, query = ''] = window.location.hash.replace(/^#\/?/, '').split('?'); const parts = path.split('/'); return { view: parts[0] === 'projects' && parts[1] ? 'project' : parts[0] === 'findings' ? parts[1] ? 'finding' : 'findings' : parts[0] === 'scans' ? 'activity' : parts[0] === 'system' ? 'system' : 'workspace', id: parts[1] || '', query }; }
function useData<T>(key: string, load: () => Promise<T>) {
  const [state, setState] = useState<{ key: string; data?: T; error?: string }>({ key });
  useEffect(() => {
    let live = true; let timer: number;
    const refresh = async () => { try { const data = await load(); if (live) setState({ key, data }); } catch (e) { if (live) setState({ key, error: e instanceof Error ? e.message : 'Ошибка загрузки' }); } if (live) timer = window.setTimeout(refresh, 5000); };
    void refresh(); return () => { live = false; window.clearTimeout(timer); };
    // key contains every resource and filter used by load.
  }, [key]);
  return state.key === key ? state : { key };
}
function Loading({ error }: { error?: string }) { return <div className={error ? 'alert error' : 'simple-empty'} role="status">{error || 'Загрузка…'}</div>; }
function Badge({ value }: { value: string }) { return <span className={`severity severity-${value.toLowerCase()}`}>{value}</span>; }
interface Summary { total: number; severity: Record<string, number>; scanners: Record<string, number>; repository_count: number; scanned_repositories: number; scan_count: number; snapshots: Scan[]; latest_runs: Scan[] }
export function SecuritySummary({ projectId = '' }: { projectId?: string }) {
  const { data, error } = useData<Summary>('summary:' + projectId, () => request('/api/security-summary?' + new URLSearchParams({ ...(projectId ? { project_id: projectId } : {}) })));
  if (!data) return <Loading error={error} />;
  const scope = { project_id: projectId, scope: 'latest' };
  return <section className="security-summary" aria-label="Сводка безопасности"><div className="summary-heading"><div><h2>Сводка безопасности</h2><p>Последние успешные проверки · проверено репозиториев: {data.scanned_repositories} из {data.repository_count}</p></div><a className="text-button" href={`#/findings?${new URLSearchParams(scope)}`}>Все находки · {data.total} →</a></div>
    <div className="stats risk-stats">{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(level => <a className={`stat risk-${level.toLowerCase()}`} key={level} href={`#/findings?${new URLSearchParams({ ...scope, severity: level })}`}><div className="stat-top">{level.charAt(0) + level.slice(1).toLowerCase()}</div><strong>{data.severity[level]}</strong><small>Открыть находки →</small></a>)}</div>
    <div className="scanner-counts">{Object.entries(data.scanners).map(([scanner, count]) => <a key={scanner} href={`#/findings?${new URLSearchParams({ ...scope, scanner })}`}><span>{scannerNames[scanner] || scanner}</span><strong>{count}</strong></a>)}<span className="summary-extra">Info: {data.severity.INFO} · Unknown: {data.severity.UNKNOWN}</span></div>
    {!data.scanned_repositories && <p className="summary-note">Успешных проверок пока нет. Нулевые значения не означают отсутствие уязвимостей.</p>}
    {data.latest_runs.some(s => s.status === 'FAILED') && <p className="alert error">Последняя проверка одного или нескольких репозиториев завершилась ошибкой. Сводка показывает предыдущие успешные результаты. <a href={`#/scans?project_id=${projectId}`}>История →</a></p>}
    {data.latest_runs.some(active) && <p className="summary-note">Новая проверка выполняется. Сводка обновится после её успешного завершения.</p>}
    {data.scanned_repositories > 0 && <p className="summary-note">Данные проверок: {date(data.snapshots[data.snapshots.length - 1]?.created_at)}{data.snapshots.length > 1 ? ` — ${date(data.snapshots[0]?.created_at)}` : ''}. Находки из повторных запусков не суммируются. Отсутствие находок не гарантирует безопасность.</p>}
  </section>;
}

export function ProjectDashboard({ id, onAdd, onStart, busy }: { id: string; onAdd: (p: Project) => void; onStart: (id: string) => void; busy: boolean }) {
  const { data: project, error } = useData<Project>('project:' + id, () => request(`/api/projects/${id}`));
  const { data: scans } = useData<Scan[]>('project-scans:' + id, () => request(`/api/scans?project_id=${id}`));
  if (!project) return <Loading error={error} />;
  return <div className="security-page"><a className="text-button" href="#/projects">← Все проекты</a><div className="project-title"><h2>{project.name}</h2><p>{project.description || 'Проверки исходного кода и зависимостей проекта.'}</p></div><SecuritySummary projectId={id} />
    <section className="panel"><div className="panel-heading"><h2>Репозитории</h2><button className="text-button" onClick={() => onAdd(project)}>Добавить репозиторий</button></div>{project.repositories.length ? project.repositories.map(repo => { const running = scans?.some(s => s.repository_id === repo.id && active(s)); return <div className="repository-row" key={repo.id}><a href={repo.url} target="_blank" rel="noreferrer">{repo.url.replace('https://github.com/', '')} ↗</a><span>{repo.default_branch}</span><button className="button secondary" disabled={busy || !scans || running} onClick={() => onStart(repo.id)}>{running ? 'Проверка выполняется' : 'Запустить проверку'}</button></div>; }) : <p className="detail-empty">Добавьте публичный репозиторий GitHub для первой проверки.</p>}</section>
    <div className="dashboard-links"><a className="button secondary" href={`#/findings?project_id=${id}&scope=latest`}>Находки проекта →</a><a className="button secondary" href={`#/scans?project_id=${id}`}>Вся история проверок →</a></div><ScanHistory query={`project_id=${id}`} projects={[project]} compact />
  </div>;
}

function SelectFilter({ label, value, options, onChange }: { label: string; value: string; options: Record<string, string>; onChange: (v: string) => void }) { return <label className="filter-label">{label}<select value={value} onChange={e => onChange(e.target.value)}>{Object.entries(options).map(([v, text]) => <option key={v} value={v}>{text}</option>)}</select></label>; }
interface Page { total: number; items: Finding[]; offset: number; limit: number }
export function FindingsPage({ query, projects }: { query: string; projects: Project[] }) {
  const params = new URLSearchParams(query); const [text, setText] = useState(params.get('q') || '');
  useEffect(() => setText(new URLSearchParams(query).get('q') || ''), [query]);
  const { data, error } = useData<Page>('findings:' + query, () => request('/api/findings-page?' + query));
  function filter(name: string, value: string) { const next = new URLSearchParams(query); next.delete('offset'); value ? next.set(name, value) : next.delete(name); if (name === 'project_id' || name === 'scope') next.delete('scan_id'); go('findings', Object.fromEntries(next)); }
  return <section className="panel"><div className="panel-heading"><div><h2>Находки <span className="count-badge">{data?.total ?? '—'}</span></h2><p>{params.get('scan_id') ? `Результаты проверки ${params.get('scan_id')?.slice(0, 8)}` : params.get('scope') === 'all' ? 'Все проверки, включая повторные и неполные' : 'Последняя успешная проверка каждого репозитория'}</p></div><a className="text-button" href="#/findings">Сбросить фильтры</a></div>
    <form className="finding-search" onSubmit={e => { e.preventDefault(); filter('q', text.trim()); }}><label>Поиск<input aria-label="Поиск находок" value={text} onChange={e => setText(e.target.value)} maxLength={200} placeholder="Название, файл, правило, пакет, CVE или CWE" /></label><button className="button secondary">Найти</button></form>
    <div className="finding-filters"><SelectFilter label="Проект" value={params.get('project_id') || ''} options={{ '': 'Все проекты', ...Object.fromEntries(projects.map(p => [p.id, p.name])) }} onChange={v => filter('project_id', v)} />
      <SelectFilter label="Проверки" value={params.get('scope') || 'latest'} options={{ latest: 'Последние успешные', all: 'Вся история' }} onChange={v => filter('scope', v)} />
      <SelectFilter label="Сканер" value={params.get('scanner') || ''} options={{ '': 'Все сканеры', ...scannerNames }} onChange={v => filter('scanner', v)} />
      <SelectFilter label="Уровень риска" value={params.get('severity') || ''} options={{ '': 'Все уровни', ...Object.fromEntries(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'].map(v => [v, v])) }} onChange={v => filter('severity', v)} />
      <SelectFilter label="Категория" value={params.get('category') || ''} options={{ '': 'Все категории', ...categories }} onChange={v => filter('category', v)} />
      <SelectFilter label="Статус" value={params.get('status') || ''} options={{ '': 'Все статусы', ...Object.fromEntries(['OPEN', 'AI_ANALYZED', 'FIX_PROPOSED', 'FIX_APPLIED', 'RECHECKING', 'VERIFIED_FIXED', 'STILL_DETECTED'].map(v => [v, labels[v]])) }} onChange={v => filter('status', v)} />
    </div>
    {!data ? <Loading error={error} /> : <><div className="findings-table-wrap"><table className="findings-table"><thead><tr><th>Уровень риска</th><th>Находка / расположение</th><th>Сканер</th><th>Статус</th></tr></thead><tbody>{data.items.map(f => <tr key={f.id}><td><Badge value={f.severity} /></td><td><a href={`#/findings/${f.id}?${new URLSearchParams({ back: query })}`} className="finding-link">{f.title}</a><small>{f.file || 'Файл не указан'}{f.line_start ? `:${f.line_start}` : ''}</small></td><td>{scannerNames[f.scanner] || f.scanner}</td><td>{labels[f.status] || f.status}</td></tr>)}</tbody></table></div>{!data.items.length && <div className="simple-empty">По выбранным условиям ничего не найдено.</div>}
    <div className="pagination"><button className="button secondary" disabled={!data.offset} onClick={() => go('findings', { ...Object.fromEntries(params), offset: String(Math.max(0, data.offset - data.limit)) })}>← Назад</button><span>{data.total ? Math.min(data.offset + 1, data.total) : 0}–{Math.min(data.offset + data.items.length, data.total)} из {data.total}</span><button className="button secondary" disabled={data.offset + data.limit >= data.total} onClick={() => go('findings', { ...Object.fromEntries(params), offset: String(data.offset + data.limit) })}>Далее →</button></div></>}
  </section>;
}

export function FindingDetail({ id, query }: { id: string; query: string }) {
  const { data: f, error } = useData<Finding>('finding:' + id, () => request(`/api/findings/${id}`));
  const back = new URLSearchParams(query).get('back') || '';
  return <div className="security-page"><a className="text-button" href={`#/findings${back ? '?' + back : ''}`}>← К списку находок</a>{!f ? <Loading error={error} /> : <><section className="panel vulnerability"><div className="finding-title"><Badge value={f.severity} /><span className="tag neutral">{labels[f.status] || f.status}</span><h2>{f.title}</h2></div><p className="finding-description">{f.description || 'Сканер не предоставил описание.'}</p><dl className="finding-facts">{[
    ['Сканер', scannerNames[f.scanner] || f.scanner], ['Уровень риска', f.severity], ['Категория', categories[f.category] || f.category], ['Файл', f.file || 'Не указан'], ['Строка', f.line_start ? String(f.line_start) + (f.line_end && f.line_end !== f.line_start ? `–${f.line_end}` : '') : 'Не указана'], ['Правило', f.rule_id], ['CVE', f.cve || 'Не указан'], ['CWE', f.cwe || 'Не указан'], ['Обнаружено', date(f.created_at)],
    ...(f.metadata.package ? [['Пакет', f.metadata.package], ['Установленная версия', f.metadata.installed_version || '—'], ['Исправленная версия', f.metadata.fixed_version || 'Не указана']] : []),
  ].map(([title, value]) => <div key={title}><dt>{title}</dt><dd>{value}</dd></div>)}</dl><div className="evidence"><h3>Evidence</h3><p>Сохранённые данные сканера. Секреты и исходный код скрыты.</p><pre>{f.evidence || 'Сканер не предоставил evidence.'}</pre></div>{f.metadata.suppressed && <p className="summary-note">В исходной конфигурации проверка была подавлена; требуется ручная оценка.</p>}{f.scanner === 'semgrep' && <p className="summary-note">Совпадение с правилом. Проверьте контекст перед исправлением.</p>}</section><div className="dashboard-links"><a href={`#/projects/${f.project_id}`} className="button secondary">Проект →</a><a href={`#/findings?scan_id=${f.scan_id}&project_id=${f.project_id}&scope=all`} className="button secondary">Все результаты этой проверки →</a><a href={`#/scans?project_id=${f.project_id}`} className="text-button">История проверок →</a></div></>}</div>;
}

export function ScanHistory({ query, projects = [], compact = false }: { query: string; projects?: Project[]; compact?: boolean }) {
  const params = new URLSearchParams(query); const projectId = params.get('project_id') || ''; const offset = Math.max(0, Number(params.get('offset')) || 0); const size = compact ? 5 : 20;
  const key = `history:${projectId}:${offset}:${size}`;
  const { data, error } = useData<Scan[]>(key, () => request('/api/scans?' + new URLSearchParams({ ...(projectId ? { project_id: projectId } : {}), offset: String(offset), limit: String(size + 1) })));
  const steps: Record<string, string> = { clone: 'Загрузка репозитория', normalize: 'Обработка результатов', store: 'Сохранение', completed: 'Завершено', ...scannerNames };
  return <section className="panel scan-history"><div className="panel-heading"><div><h2>{compact ? 'Последние проверки' : 'История проверок'}</h2><p>Статусы обновляются автоматически</p></div>{!compact && <SelectFilter label="Проект" value={projectId} options={{ '': 'Все проекты', ...Object.fromEntries(projects.map(p => [p.id, p.name])) }} onChange={v => go('scans', { project_id: v })} />}</div>
    {!data ? <Loading error={error} /> : !data.length ? <div className="simple-empty">Проверок пока нет.</div> : <div className="history-list">{data.slice(0, size).map(s => <article key={s.id}><div className="history-heading"><div><a href={`#/projects/${s.project_id}`}>{projects.find(p => p.id === s.project_id)?.name || 'Проверка проекта'}</a><p>{date(s.created_at)} · {s.id.slice(0, 8)}</p></div><span className={`tag ${s.status === 'COMPLETED' ? 'mint' : 'neutral'}`}>{labels[s.status] || s.status}</span></div><div className="history-meta"><span>Commit: <code>{s.commit_sha?.slice(0, 7) || '—'}</code></span><span>Этап: {steps[s.current_step || ''] || 'В очереди'}</span><span>Длительность: {s.started_at && s.completed_at ? `${Math.max(0, Math.round((Date.parse(s.completed_at) - Date.parse(s.started_at)) / 1000))} сек.` : '—'}</span></div><div className="history-scanners">{Object.entries(s.scanner_results).map(([name, result]) => <span key={name}>{scannerNames[name] || name}: {labels[result.status] || result.status}{result.finding_count !== undefined ? ` · находок: ${result.finding_count}` : ''}{result.error && <strong className="form-error"> · {result.error}</strong>}</span>)}</div>{s.error_message && <p className="form-error">{s.error_message}</p>}{Object.values(s.scanner_results).some(r => r.status === 'COMPLETED') && <a className="text-button" href={`#/findings?scan_id=${s.id}&project_id=${s.project_id}&scope=all`}>Результаты →</a>}</article>)}</div>}
    {!compact && data && <div className="pagination"><button className="button secondary" disabled={!offset} onClick={() => go('scans', { project_id: projectId, offset: String(Math.max(0, offset - size)) })}>← Назад</button><span>Страница {Math.floor(offset / size) + 1}</span><button className="button secondary" disabled={data.length <= size} onClick={() => go('scans', { project_id: projectId, offset: String(offset + size) })}>Далее →</button></div>}
  </section>;
}
