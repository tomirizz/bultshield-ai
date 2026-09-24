import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { Activity, ArrowRight, ArrowUpRight, Blocks, BrainCircuit, Check, ChevronRight, Circle, CodeXml, Database, ExternalLink, FolderGit2, GitBranch, Globe, KeyRound, Layers, LayoutDashboard, LoaderCircle, Moon, Package, Plus, RefreshCw, ScanLine, Search, Server, ShieldCheck, ShieldEllipsis, Sun, X } from 'lucide-react';
import { api } from './api';
import type { Finding, NewProject, Overview, Project, Readiness, Scan } from './api';

type View = 'workspace' | 'findings' | 'activity' | 'system';
const nav = [
  { id: 'workspace' as const, label: 'Проекты', icon: LayoutDashboard },
  { id: 'findings' as const, label: 'Находки', icon: ShieldEllipsis },
  { id: 'activity' as const, label: 'Сканирования', icon: Activity },
  { id: 'system' as const, label: 'Система', icon: Blocks },
];
const tools = [
  { name: 'Gitleaks', role: 'Secrets', icon: KeyRound },
  { name: 'Semgrep CE', role: 'Source code', icon: CodeXml },
  { name: 'Trivy', role: 'Dependencies / config', icon: Package },
  { name: 'Nuclei', role: 'Web application', icon: Globe },
];
const date = (value: string) => new Intl.DateTimeFormat('ru-RU', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }).format(new Date(value));

function Dialog({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => { ref.current?.showModal(); }, []);
  return <dialog ref={ref} className="modal" onCancel={onClose} onClose={onClose} aria-labelledby="dialog-title">
    <div className="modal-heading"><div><span className="eyebrow">BULTSHIELD WORKSPACE</span><h2 id="dialog-title">{title}</h2></div><button className="icon-button" type="button" onClick={onClose} aria-label="Закрыть"><X size={18} /></button></div>
    {children}
  </dialog>;
}

function ProjectForm({ onClose, onSaved }: { onClose: () => void; onSaved: (project: Project) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError('');
    const form = new FormData(event.currentTarget);
    const url = String(form.get('url') || '').trim();
    const data: NewProject = { name: String(form.get('name')).trim(), description: String(form.get('description') || '').trim(), target_url: String(form.get('target_url') || '').trim() || null, repository: url ? { url, default_branch: String(form.get('branch') || 'main').trim() } : null };
    try { onSaved(await api.createProject(data)); } catch (e) { setError(e instanceof Error ? e.message : 'Не удалось создать проект'); setBusy(false); }
  }
  return <Dialog title="Новый проект" onClose={busy ? () => {} : onClose}><form onSubmit={submit}>
    <label>Название проекта<input name="name" required maxLength={100} placeholder="Например, Customer Portal" autoFocus /></label>
    <label>Описание <span className="optional">необязательно</span><textarea name="description" maxLength={1000} placeholder="Что проверяем в этом проекте" rows={2} /></label>
    <div className="form-divider"><GitBranch size={15} /> Репозиторий</div>
    <label>Public GitHub URL <span className="optional">можно добавить позже</span><input name="url" type="url" maxLength={512} placeholder="https://github.com/owner/repository" /></label>
    <div className="form-two"><label>Ветка<input name="branch" defaultValue="main" maxLength={200} required /></label><label>Test / staging URL <span className="optional">необязательно</span><input name="target_url" type="url" maxLength={2048} placeholder="https://staging.example.com" /></label></div>
    <p className="form-help">После создания проекта нажмите «Запустить проверку». Доступность репозитория проверяется при запуске.</p>
    {error && <p className="form-error" role="alert">{error}</p>}
    <div className="modal-actions"><button className="button secondary" type="button" disabled={busy} onClick={onClose}>Отмена</button><button className="button primary" disabled={busy}>{busy ? <LoaderCircle size={16} className="spin" /> : <Plus size={16} />} {busy ? 'Сохраняем…' : 'Создать проект'}</button></div>
  </form></Dialog>;
}

function RepositoryForm({ project, onClose, onSaved }: { project: Project; onClose: () => void; onSaved: () => void }) {
  const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError('');
    const form = new FormData(event.currentTarget);
    try { await api.addRepository(project.id, String(form.get('url')), String(form.get('branch'))); onSaved(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Ошибка сохранения'); setBusy(false); }
  }
  return <Dialog title="Добавить репозиторий" onClose={busy ? () => {} : onClose}><form onSubmit={submit}>
    <p className="form-help">Проект: {project.name}</p>
    <label>Public GitHub URL<input name="url" type="url" required autoFocus maxLength={512} placeholder="https://github.com/owner/repository" /></label>
    <label>Ветка<input name="branch" required defaultValue="main" maxLength={200} /></label>
    {error && <p className="form-error" role="alert">{error}</p>}
    <div className="modal-actions"><button className="button secondary" type="button" onClick={onClose} disabled={busy}>Отмена</button><button className="button primary" disabled={busy}>{busy ? 'Сохраняем…' : 'Сохранить репозиторий'}</button></div>
  </form></Dialog>;
}

function EmptyState({ icon, title, children, action }: { icon: ReactNode; title: string; children: ReactNode; action?: ReactNode }) {
  return <div className="empty-state"><div className="empty-art"><span className="orbit orbit-one" /><span className="orbit orbit-two" /><div className="empty-symbol">{icon}</div><span className="tiny-signal"><Check size={12} /></span></div><h3>{title}</h3><p>{children}</p>{action}</div>;
}

export default function App() {
  const [view, setView] = useState<View>('workspace');
  const [projects, setProjects] = useState<Project[]>([]);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingScanId, setFindingScanId] = useState('');
  const [scanner, setScanner] = useState('ALL');
  const [refreshFailed, setRefreshFailed] = useState(false);
  const refreshSequence = useRef(0);
  const [loading, setLoading] = useState(true); const [error, setError] = useState(''); const [notice, setNotice] = useState('');
  const [search, setSearch] = useState(''); const [severity, setSeverity] = useState('ALL');
  const [createOpen, setCreateOpen] = useState(false); const [repositoryOpen, setRepositoryOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [startingScan, setStartingScan] = useState<string | null>(null);
  const [theme, setTheme] = useState(() => localStorage.getItem('bultshield-theme') || 'dark');
  useEffect(() => { document.documentElement.dataset.theme = theme; localStorage.setItem('bultshield-theme', theme); }, [theme]);
  const refresh = useCallback(async (silent = false) => {
    const sequence = ++refreshSequence.current;
    if (!silent) { setLoading(true); setError(''); }
    const results = await Promise.allSettled([
      api.readiness(), api.overview(), api.projects(), api.scans(), api.findings(findingScanId),
    ] as const);
    if (sequence !== refreshSequence.current) return;
    setReadiness(results[0].status === 'fulfilled' ? results[0].value : null);
    setOverview(results[1].status === 'fulfilled' ? results[1].value : null);
    if (results[2].status === 'fulfilled') setProjects(results[2].value);
    if (results[3].status === 'fulfilled') setScans(results[3].value);
    if (results[4].status === 'fulfilled') setFindings(results[4].value);
    setRefreshFailed(results.some(result => result.status === 'rejected'));
    setLoading(false);
  }, [findingScanId]);
  useEffect(() => {
    let active = true;
    let timer: number | undefined;
    const poll = async (initial = false) => {
      if (initial || document.visibilityState === 'visible') await refresh(!initial);
      if (active) timer = window.setTimeout(() => void poll(), 5000);
    };
    void poll(true);
    return () => { active = false; window.clearTimeout(timer); ++refreshSequence.current; };
  }, [refresh]);
  const selected = projects.find(project => project.id === selectedId);
  const isReady = readiness?.status === 'ready';
  const shown = projects.filter(project => `${project.name} ${project.repositories.map(repo => repo.url).join(' ')}`.toLowerCase().includes(search.toLowerCase()));
  const filteredFindings = findings.filter(finding => (severity === 'ALL' || finding.severity === severity) && (scanner === 'ALL' || finding.scanner === scanner));
  const navigate = (next: View) => { setView(next); setNotice(''); };
  function repositoryIsScanning(repositoryId: string) {
    return scans.some(scan =>
      scan.repository_id === repositoryId &&
      ['QUEUED', 'CLONING', 'SCANNING', 'NORMALIZING', 'AI_ANALYSIS']
        .includes(scan.status)
    );
  }

  async function startScan(repositoryId: string) {
    setStartingScan(repositoryId);
    setError('');
    setNotice('');

    try {
      await api.startScan(repositoryId);
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : 'Не удалось создать сканирование.'
      );
      setStartingScan(null);
      return;
    }

    setNotice('Проверка Gitleaks + Semgrep добавлена в очередь.');
    setView('activity');
    await refresh();
    setStartingScan(null);
  }
  async function created(project: Project) { setCreateOpen(false); setSelectedId(project.id); setNotice(`Проект «${project.name}» сохранён в PostgreSQL.`); await refresh(); }

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#" onClick={event => { event.preventDefault(); navigate('workspace'); }}><span className="brand-mark"><ShieldCheck size={23} /></span><span>BultShield</span><span className="ai-tag">AI</span></a>
      <div className="workspace-label"><span className="workspace-avatar">B</span><div>Security workspace<small>Single workspace · MVP</small></div><ChevronRight size={14} /></div>
      <p className="nav-label">WORKSPACE</p>
      <nav aria-label="Основная навигация">{nav.map(item => <button key={item.id} className={`nav-item ${view === item.id ? 'active' : ''}`} onClick={() => navigate(item.id)} aria-current={view === item.id ? 'page' : undefined}><item.icon size={18} /><span>{item.label}</span>{item.id === 'workspace' && overview && <span className="nav-count">{overview.projects}</span>}</button>)}</nav>
      <div className="sidebar-bottom"><div className="stage-progress"><span>Этап 04</span><span>+ Semgrep</span></div><div className="stage-track"><span /></div><p>GitHub → Gitleaks + Semgrep → Dashboard</p><div className="hosting-label"><Server size={15} /> Целевая платформа: Bult.ai</div></div>
    </aside>
    <div className="app-content">
      <header className="topbar"><div className="breadcrumbs">Workspace <ChevronRight size={13} /><span>{nav.find(item => item.id === view)?.label}</span></div><div className="topbar-actions"><span className={`connection ${isReady ? 'connected' : loading ? '' : 'disconnected'}`}><span />{loading ? 'Подключение…' : isReady ? 'PostgreSQL connected' : 'БД недоступна'}</span><button className="icon-button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label={theme === 'dark' ? 'Светлая тема' : 'Тёмная тема'}>{theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}</button><span className="user-avatar">BS</span></div></header>
      <main className="main-content">
        <div className="page-heading"><div><div className="eyebrow">BULTSHIELD AI / CODE & SECRET SCANNING</div><h1>{view === 'workspace' ? 'Безопасность начинается здесь.' : view === 'findings' ? 'Единый список находок' : view === 'activity' ? 'История сканирований' : 'Основа системы'}</h1><p>{view === 'workspace' ? 'Проверьте публичный GitHub-репозиторий на секреты и опасные конструкции кода.' : view === 'findings' ? 'Находки Gitleaks и Semgrep в одном списке. Исходный код и секреты скрыты; результаты требуют проверки.' : view === 'activity' ? 'Каждый запуск, его статус и результат — в одном месте.' : 'Целевая платформа — Bult.ai. Архитектура готова к расширению.'}</p></div><div className="heading-actions"><button className="button secondary compact" onClick={() => void refresh()} disabled={loading} aria-label="Обновить данные"><RefreshCw size={16} className={loading ? 'spin' : ''} /><span>Обновить</span></button>{view === 'workspace' && <button className="button primary" onClick={() => setCreateOpen(true)} disabled={!isReady}><Plus size={16} />Новый проект</button>}</div></div>
        {readiness?.environment === 'development' && <div className="preview-note"><Server size={14} />Локальная проверка · целевая платформа — Bult.ai</div>}
        {refreshFailed && <div className="alert error" role="status">Не удалось обновить данные. Показаны последние полученные результаты. Повторите обновление.</div>}
        {error && <div className="alert error" role="alert">{error}</div>}
        {notice && <div className="alert success" role="status"><Check size={16} />{notice}<button className="icon-button" onClick={() => setNotice('')} aria-label="Скрыть уведомление"><X size={15} /></button></div>}
        {view === 'workspace' && <>
          <section className="stats" aria-label="Состояние рабочего пространства">{[
            { title: 'Проекты', value: overview?.projects, icon: FolderGit2, foot: 'В рабочем пространстве' },
            { title: 'Репозитории', value: overview?.repositories, icon: GitBranch, foot: 'Сохранённые GitHub URL' },
            { title: 'Сканирования', value: overview?.scans, icon: ScanLine, foot: 'Проверки текущих файлов ветки' },
            { title: 'Находки', value: overview?.findings, icon: ShieldEllipsis, foot: 'Секреты замаскированы' },
          ].map(stat => <article className="stat" key={stat.title}><div className="stat-top"><span>{stat.title}</span><stat.icon size={17} /></div><strong>{stat.value ?? '—'}</strong><small>{stat.foot}</small></article>)}</section>
          <section className="panel projects-panel"><div className="panel-heading"><div><h2>Ваши проекты <span className="count-badge">{overview?.projects ?? '—'}</span></h2><p>Репозитории и настройки проверок</p></div><label className="search-box"><Search size={15} /><input aria-label="Поиск проектов" placeholder="Найти проект…" value={search} onChange={event => setSearch(event.target.value)} /></label></div>
            {loading && !overview ? <div className="loading-state"><LoaderCircle className="spin" size={22} />Загружаем рабочее пространство…</div> : !overview ? <EmptyState icon={<Database size={28} />} title="Нет соединения с данными">После подключения PostgreSQL здесь появятся ваши проекты.</EmptyState> : projects.length === 0 ? <EmptyState icon={<FolderGit2 size={31} />} title="Подготовим ваш первый проект" action={<button className="button secondary" onClick={() => setCreateOpen(true)}><Plus size={16} />Добавить проект</button>}>Сохраните публичный GitHub URL и ветку, затем запустите проверку.</EmptyState> : shown.length === 0 ? <div className="simple-empty">Проекты по этому запросу не найдены.</div> : <div className="project-list">{shown.map(project => <button className={`project-row ${selectedId === project.id ? 'selected' : ''}`} key={project.id} onClick={() => setSelectedId(project.id)}><span className="project-icon"><FolderGit2 size={20} /></span><span className="project-main"><strong>{project.name}</strong><small>{project.repositories[0]?.url.replace('https://github.com/', '') || 'Репозиторий пока не добавлен'}</small></span><span className="project-branch"><GitBranch size={13} />{project.repositories[0]?.default_branch || '—'}</span><span className="project-date">{date(project.created_at)}</span><span className="tag neutral">Настройки сохранены</span><ChevronRight size={16} /></button>)}</div>}
          </section>
          {selected && <section className="panel project-detail"><div className="panel-heading"><div><span className="eyebrow">PROJECT DETAILS</span><h2>{selected.name}</h2>{selected.description && <p>{selected.description}</p>}</div><button className="icon-button" onClick={() => setSelectedId(null)} aria-label="Скрыть детали проекта"><X size={18} /></button></div>
            <div className="detail-toolbar"><span><GitBranch size={15} />Репозитории · {selected.repositories.length}</span><button className="text-button" onClick={() => setRepositoryOpen(true)}><Plus size={14} />Добавить репозиторий</button></div>
            {selected.repositories.length ? (
              selected.repositories.map(repo => (
                <div className="repository-row" key={repo.id}>
                  <a href={repo.url} target="_blank" rel="noreferrer">
                    {repo.url.replace('https://github.com/', '')}
                    <ArrowUpRight size={14} />
                  </a>

                  <span>
                    <GitBranch size={13} />
                    {repo.default_branch}
                  </span>

                  <button
                    className="button secondary compact"
                    type="button"
                    disabled={
                      !isReady ||
                      startingScan !== null ||
                      repositoryIsScanning(repo.id)
                    }
                    onClick={() => void startScan(repo.id)}
                  >
                    {startingScan === repo.id ? (
                      <LoaderCircle size={16} className="spin" />
                    ) : (
                      <ScanLine size={16} />
                    )}

                    {startingScan === repo.id
                      ? 'Добавляем…'
                      : repositoryIsScanning(repo.id)
                        ? 'Проверка выполняется'
                        : 'Запустить проверку'}
                  </button>
                </div>
              ))
            ) : (
              <p className="detail-empty">
                Добавьте public GitHub-репозиторий.
              </p>
            )}
            <div className="project-target"><Globe size={15} /><span>Staging: {selected.target_url || 'не указан'}</span></div>
            <div className="scan-unavailable">
              <span>
                <ScanLine size={17} />
                Gitleaks ищет секреты; Semgrep проверяет Python, JavaScript и TypeScript.
                Анализируются текущие файлы ветки, без истории Git. Исходный код и секреты скрываются.
              </span>
            </div>
          </section>}
          <div className="bottom-grid"><section className="panel scanner-panel"><div className="panel-heading"><div><h2>Security toolkit</h2><p>Четыре инструмента · один формат findings</p></div><span className="tag neutral">2 сканера</span></div><div className="scanner-list">{tools.map(tool => <div className="scanner-row" key={tool.name}><div className="tool-icon"><tool.icon size={18} /></div><div><strong>{tool.name}</strong><small>{tool.role}</small></div><span className="tool-status"><Circle size={7} />{['Gitleaks', 'Semgrep CE'].includes(tool.name) ? 'Подключён' : 'Следующий этап'}</span></div>)}</div></section>
            <section className="panel pipeline-panel"><div className="panel-heading"><div><h2>От находки к результату</h2><p>Целевой цикл продукта</p></div><ArrowUpRight size={17} /></div><div className="pipeline">{[{ name: 'Detect', desc: 'Найти уязвимости', icon: ScanLine }, { name: 'Understand', desc: 'Объяснить с помощью AI', icon: BrainCircuit }, { name: 'Fix', desc: 'Предложить исправление', icon: CodeXml }, { name: 'Verify', desc: 'Проверить повторным scan', icon: ShieldCheck }].map((step, index) => <div className="pipeline-item" key={step.name}><span className="pipeline-number">0{index + 1}</span><step.icon size={17} /><strong>{step.name}</strong><span>{step.desc}</span></div>)}</div><div className="pipeline-foot"><span className="small-dot" />Исправление применяет пользователь</div></section></div>
        </>}
        {view === 'findings' && <section className="panel"><div className="panel-heading"><div><h2>Findings <span className="count-badge">{overview?.findings ?? '—'}</span></h2><p>Gitleaks + Semgrep · максимум 100 последних находок · связанные результаты сохраняются отдельно</p><label className="filter-label">Сканирование<select value={findingScanId} onChange={event => { setFindings([]); setFindingScanId(event.target.value); }}><option value="">Все последние</option>{scans.map(scan => <option key={scan.id} value={scan.id}>{date(scan.created_at)} · {scan.status} · {scan.id.slice(0, 8)}</option>)}</select></label></div><label className="filter-label">Сканер<select value={scanner} onChange={event => setScanner(event.target.value)}><option value="ALL">Оба сканера</option><option value="gitleaks">Gitleaks</option><option value="semgrep">Semgrep</option></select></label><label className="filter-label">Severity<select value={severity} onChange={event => setSeverity(event.target.value)}><option value="ALL">Все уровни</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'].map(value => <option key={value}>{value}</option>)}</select></label></div>{filteredFindings.length ? <div className="result-list">{filteredFindings.map(finding => <article key={finding.id}><span className={`severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span><div><h3>{finding.title}</h3><p>{finding.scanner} · {finding.file || finding.category}{finding.line_start ? `:${finding.line_start}` : ''}</p></div><span className="tag neutral">{finding.status}</span><details><summary>Детали</summary><p>{finding.description}</p><p>Правило: {finding.rule_id}</p>{finding.cwe && <p>CWE: {finding.cwe}</p>}<p>Исходные данные: <code>{finding.evidence}</code></p>{finding.scanner === 'semgrep' && <p>Совпадение с правилом; проверьте контекст перед исправлением.</p>}<p>Scan: {finding.scan_id.slice(0, 8)}</p></details></article>)}</div> : <EmptyState icon={<ShieldEllipsis size={32} />} title={findings.length ? 'Нет находок с такими фильтрами' : 'Нет находок в выбранных результатах'}>Проверьте статус во вкладке «Сканирования». Ноль находок при COMPLETED означает, что выполненные правила ничего не обнаружили в проверенной области. Это не гарантирует отсутствие уязвимостей. Semgrep проверяет Python, JavaScript и TypeScript.</EmptyState>}</section>}
        {view === 'activity' && <section className="panel"><div className="panel-heading"><div><h2>Запуски <span className="count-badge">{overview?.scans ?? '—'}</span></h2><p>История сохраняется в PostgreSQL</p></div><span className="tag neutral">Gitleaks + Semgrep · обновление каждые 5 сек</span></div>{scans.length ? <div className="result-list">{scans.map(scan => <article key={scan.id}><ScanLine size={19} /><div><h3>{projects.find(project => project.id === scan.project_id)?.name || 'Project'}</h3><p>{date(scan.created_at)} · {scan.commit_sha?.slice(0, 7) || 'Ожидание commit SHA'}</p>{Object.entries(scan.scanner_results).map(([name, result]) => <p key={name}>{name}: {result.status}{result.finding_count !== undefined ? ` · находок: ${result.finding_count}` : ''}{result.scanned_files !== undefined ? ` · файлов: ${result.scanned_files}` : ''}{result.error && <span className="form-error"> · {result.error}</span>}</p>)}{scan.error_message && <p className="form-error" role="alert">{scan.error_message}</p>}</div><span className={`tag ${scan.status === 'COMPLETED' ? 'mint' : 'neutral'}`}>{scan.status}</span>{Object.values(scan.scanner_results).some(result => result.status === 'COMPLETED') && <button className="text-button" onClick={() => { setFindings([]); setFindingScanId(scan.id); setView('findings'); }}>Результаты <ArrowRight size={14} /></button>}</article>)}</div> : <EmptyState icon={<Activity size={31} />} title="Первый scan ещё впереди">Откройте проект и нажмите «Запустить проверку» рядом с репозиторием.</EmptyState>}<div className="lifecycle-strip">{['QUEUED', 'CLONING', 'SCANNING', 'NORMALIZING', 'COMPLETED'].map((state, i) => <span key={state}>{i > 0 && <ArrowRight size={12} />}{state}</span>)}</div></section>}
        {view === 'system' && <>
          <section className="panel"><div className="panel-heading"><div><h2>Bult.ai infrastructure</h2><p>App, PostgreSQL и отдельный worker со сканерами</p></div><span className="tag mint">Этап 04</span></div><div className="service-grid">{[{ name: 'App', desc: 'React + FastAPI', icon: LayoutDashboard, state: isReady ? 'Работает' : 'Проверяется', enabled: isReady }, { name: 'PostgreSQL', desc: 'Данные + схема очереди', icon: Database, state: isReady ? 'Подключена' : 'Нет соединения', enabled: isReady }, { name: 'Worker', desc: 'Gitleaks + Semgrep CE · очередь PostgreSQL', icon: ScanLine, state: scans.some(scan => scan.status === 'COMPLETED') ? 'Есть выполненные проверки' : 'Ожидает первой проверки', enabled: scans.some(scan => scan.status === 'COMPLETED') }, { name: 'LLM Server', desc: 'llama.cpp + локальная модель', icon: BrainCircuit, state: 'Следующий этап', enabled: false }].map(service => <div className="service-card" key={service.name}><service.icon size={22} /><h3>{service.name}</h3><p>{service.desc}</p><span className={`tag ${service.enabled ? 'mint' : 'neutral'}`}>{service.state}</span></div>)}</div><p className="system-note">Worker размещается внутри Bult.ai. LLM Server будет подключён на следующем этапе, также на Bult.ai. Внешний LLM API не используется.</p></section>
          <div className="bottom-grid"><section className="panel"><div className="panel-heading"><div><h2>Модель данных</h2><p>9 таблиц приложения · Alembic migrations</p></div><Database size={19} /></div><div className="schema-list">{['users', 'projects', 'repositories', 'scans', 'findings', 'ai_analyses', 'fixes', 'rescans', 'scan_jobs'].map(table => <span key={table}><Layers size={13} />{table}</span>)}</div><div className="system-note">users пока содержит только владельца общего MVP workspace. Регистрация и вход не включены.</div></section><section className="panel"><div className="panel-heading"><div><h2>Состояние приложения</h2><p>Ответ настоящего backend</p></div><Activity size={18} /></div><dl className="system-facts"><div><dt>Версия</dt><dd>0.4.0</dd></div><div><dt>Database</dt><dd>{readiness?.database || 'unavailable'}</dd></div><div><dt>Schema revision</dt><dd>{readiness?.schema_revision || '—'}</dd></div><div><dt>Environment</dt><dd>{readiness?.environment || '—'}</dd></div></dl><a className="text-button" href="/api/openapi.json" target="_blank" rel="noreferrer">OpenAPI schema<ExternalLink size={13} /></a></section></div>
        </>}
        <footer className="footer"><span><ShieldCheck size={14} />BultShield AI <span className="footer-dot">·</span> Gitleaks + Semgrep · v0.4.0</span><span>Detect <ArrowRight size={11} /> Understand <ArrowRight size={11} /> Fix <ArrowRight size={11} /> Verify</span></footer>
      </main>
    </div>
    {createOpen && <ProjectForm onClose={() => setCreateOpen(false)} onSaved={project => void created(project)} />}
    {repositoryOpen && selected && <RepositoryForm project={selected} onClose={() => setRepositoryOpen(false)} onSaved={() => { setRepositoryOpen(false); setNotice('Репозиторий сохранён.'); void refresh(); }} />}
  </div>;
}
