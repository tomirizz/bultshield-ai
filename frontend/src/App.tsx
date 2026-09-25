import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { Activity, Blocks, Check, ChevronRight, Circle, CodeXml, Database, ExternalLink, FolderGit2, GitBranch, KeyRound, LayoutDashboard, LoaderCircle, Moon, Package, Plus, RefreshCw, ScanLine, Search, Server, ShieldCheck, ShieldEllipsis, Sun, X } from 'lucide-react';
import { api } from './api';
import type { NewProject, Overview, Project, Readiness, Scan } from './api';

import { FindingDetail, FindingsPage, ProjectDashboard, ScanHistory, SecuritySummary, go, readRoute } from './SecurityPages';

type View = 'workspace' | 'findings' | 'activity' | 'system';
const nav = [
  { id: 'workspace' as const, label: 'Проекты', icon: LayoutDashboard },
  { id: 'findings' as const, label: 'Находки', icon: ShieldEllipsis },
  { id: 'activity' as const, label: 'Сканирования', icon: Activity },
  { id: 'system' as const, label: 'Система', icon: Blocks },
];
const tools = [
  { name: 'Gitleaks', role: 'Поиск секретов', icon: KeyRound },
  { name: 'Semgrep CE', role: 'Проверка кода', icon: CodeXml },
  { name: 'Trivy', role: 'Зависимости и конфигурация', icon: Package },
];
const date = (value: string) => new Intl.DateTimeFormat('ru-RU', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }).format(new Date(value));

function Dialog({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => { ref.current?.showModal(); }, []);
  return <dialog ref={ref} className="modal" onCancel={onClose} onClose={onClose} aria-labelledby="dialog-title">
    <div className="modal-heading"><div><h2 id="dialog-title">{title}</h2></div><button className="icon-button" type="button" onClick={onClose} aria-label="Закрыть"><X size={18} /></button></div>
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
    <label>Публичный репозиторий GitHub <span className="optional">можно добавить позже</span><input name="url" type="url" maxLength={512} placeholder="https://github.com/owner/repository" /></label>
    <label>Ветка<input name="branch" defaultValue="main" maxLength={200} required /></label>
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
    <label>Публичный репозиторий GitHub<input name="url" type="url" required autoFocus maxLength={512} placeholder="https://github.com/owner/repository" /></label>
    <label>Ветка<input name="branch" required defaultValue="main" maxLength={200} /></label>
    {error && <p className="form-error" role="alert">{error}</p>}
    <div className="modal-actions"><button className="button secondary" type="button" onClick={onClose} disabled={busy}>Отмена</button><button className="button primary" disabled={busy}>{busy ? 'Сохраняем…' : 'Сохранить репозиторий'}</button></div>
  </form></Dialog>;
}

function EmptyState({ icon, title, children, action }: { icon: ReactNode; title: string; children: ReactNode; action?: ReactNode }) {
  return <div className="empty-state"><div className="empty-symbol">{icon}</div><h3>{title}</h3><p>{children}</p>{action}</div>;
}

export default function App() {
  const [route, setRoute] = useState(readRoute);
  const view = route.view;
  const [pageRevision, setPageRevision] = useState(0);
  useEffect(() => { const changed = () => { setRoute(readRoute()); window.scrollTo(0, 0); }; window.addEventListener('hashchange', changed); return () => window.removeEventListener('hashchange', changed); }, []);
  const [projects, setProjects] = useState<Project[]>([]);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [refreshFailed, setRefreshFailed] = useState(false);
  const refreshSequence = useRef(0);
  const [loading, setLoading] = useState(true); const [error, setError] = useState(''); const [notice, setNotice] = useState('');
  const [search, setSearch] = useState('');
  const [createOpen, setCreateOpen] = useState(false); const [repositoryOpen, setRepositoryOpen] = useState(false);
  const [selected, setSelected] = useState<Project | null>(null);
  const [startingScan, setStartingScan] = useState<string | null>(null);
  const [theme, setTheme] = useState(() => localStorage.getItem('bultshield-theme') || 'dark');
  useEffect(() => { document.documentElement.dataset.theme = theme; localStorage.setItem('bultshield-theme', theme); }, [theme]);
  const refresh = useCallback(async (silent = false) => {
    const sequence = ++refreshSequence.current;
    if (!silent) { setLoading(true); setError(''); }
    const results = await Promise.allSettled([
      api.readiness(), api.overview(), api.projects(), api.scans(),
    ] as const);
    if (sequence !== refreshSequence.current) return;
    setReadiness(results[0].status === 'fulfilled' ? results[0].value : null);
    setOverview(results[1].status === 'fulfilled' ? results[1].value : null);
    if (results[2].status === 'fulfilled') setProjects(results[2].value);
    if (results[3].status === 'fulfilled') setScans(results[3].value);
    setRefreshFailed(results.some(result => result.status === 'rejected'));
    setLoading(false);
  }, []);
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
  const isReady = readiness?.status === 'ready';
  const shown = projects.filter(project => `${project.name} ${project.repositories.map(repo => repo.url).join(' ')}`.toLowerCase().includes(search.toLowerCase()));
  const navigate = (next: View) => { go(next === 'workspace' ? 'projects' : next === 'activity' ? 'scans' : next); setNotice(''); };
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

    setNotice('Проверка добавлена в очередь.');
    go('scans');
    await refresh();
    setStartingScan(null);
  }
  async function created(project: Project) { setCreateOpen(false); go('projects/' + project.id); setNotice(`Проект «${project.name}» создан.`); await refresh(); }

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#" onClick={event => { event.preventDefault(); navigate('workspace'); }}><span className="brand-mark"><ShieldCheck size={23} /></span><span>BultShield</span></a>
      <div className="workspace-label"><span className="workspace-avatar">B</span><div>Рабочая область<small>Анализ репозиториев</small></div><ChevronRight size={14} /></div>
      <p className="nav-label">НАВИГАЦИЯ</p>
      <nav aria-label="Основная навигация">{nav.map(item => <button key={item.id} className={`nav-item ${(view === 'project' ? 'workspace' : view === 'finding' ? 'findings' : view) === item.id ? 'active' : ''}`} onClick={() => navigate(item.id)} aria-current={(view === 'project' ? 'workspace' : view === 'finding' ? 'findings' : view) === item.id ? 'page' : undefined}><item.icon size={18} /><span>{item.label}</span>{item.id === 'workspace' && overview && <span className="nav-count">{overview.projects}</span>}</button>)}</nav>
      <div className="sidebar-bottom"><p>BultShield · 0.7.0</p><p>Статический анализ кода</p></div>
    </aside>
    <div className="app-content">
      <header className="topbar"><div className="breadcrumbs">BultShield <ChevronRight size={13} /><span>{view === 'project' ? 'Обзор проекта' : view === 'finding' ? 'Карточка находки' : nav.find(item => item.id === view)?.label}</span></div><div className="topbar-actions"><span className={`connection ${isReady ? 'connected' : loading ? '' : 'disconnected'}`}><span />{loading ? 'Подключение…' : isReady ? 'Подключено' : 'Нет соединения'}</span><button className="icon-button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label={theme === 'dark' ? 'Светлая тема' : 'Тёмная тема'}>{theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}</button><span className="user-avatar">BS</span></div></header>
      <main className="main-content">
        <div className="page-heading"><div><h1>{view === 'project' ? 'Обзор проекта' : view === 'finding' ? 'Карточка находки' : view === 'workspace' ? 'Проекты' : view === 'findings' ? 'Результаты проверок' : view === 'activity' ? 'История сканирований' : 'Состояние системы'}</h1><p>{view === 'project' ? 'Результаты проверок и история проекта.' : view === 'finding' ? 'Подробности результата сканирования.' : view === 'workspace' ? 'Добавьте репозиторий GitHub и запустите проверку.' : view === 'findings' ? 'Секреты, ошибки кода, уязвимости зависимостей и конфигурации.' : view === 'activity' ? 'История запусков и результаты сканеров.' : 'Подключение к базе данных и сведения о приложении.'}</p></div><div className="heading-actions"><button className="button secondary compact" onClick={() => { setPageRevision(n => n + 1); void refresh(); }} disabled={loading} aria-label="Обновить данные"><RefreshCw size={16} className={loading ? 'spin' : ''} /><span>Обновить</span></button>{view === 'workspace' && <button className="button primary" onClick={() => setCreateOpen(true)} disabled={!isReady}><Plus size={16} />Новый проект</button>}</div></div>
        {readiness?.environment === 'development' && <div className="preview-note"><Server size={14} />Локальное окружение</div>}
        {refreshFailed && <div className="alert error" role="status">Не удалось обновить данные. Показаны последние полученные результаты. Повторите обновление.</div>}
        {error && <div className="alert error" role="alert">{error}</div>}
        {notice && <div className="alert success" role="status"><Check size={16} />{notice}<button className="icon-button" onClick={() => setNotice('')} aria-label="Скрыть уведомление"><X size={15} /></button></div>}
        {view === 'workspace' && <>
          <SecuritySummary key={pageRevision} />
          <section className="stats" aria-label="Состояние рабочего пространства">{[
            { title: 'Проекты', value: overview?.projects, icon: FolderGit2, foot: 'В рабочем пространстве' },
            { title: 'Репозитории', value: overview?.repositories, icon: GitBranch, foot: 'Подключены к проектам' },
            { title: 'Сканирования', value: overview?.scans, icon: ScanLine, foot: 'Проверки текущих файлов ветки' },
            { title: 'Находки', value: overview?.findings, icon: ShieldEllipsis, foot: 'За все проверки' },
          ].map(stat => <article className="stat" key={stat.title}><div className="stat-top"><span>{stat.title}</span><stat.icon size={17} /></div><strong>{stat.value ?? '—'}</strong><small>{stat.foot}</small></article>)}</section>
          <section className="panel projects-panel"><div className="panel-heading"><div><h2>Список проектов <span className="count-badge">{overview?.projects ?? '—'}</span></h2><p>Репозитории и настройки проверок</p></div><label className="search-box"><Search size={15} /><input aria-label="Поиск проектов" placeholder="Найти проект…" value={search} onChange={event => setSearch(event.target.value)} /></label></div>
            {loading && !overview ? <div className="loading-state"><LoaderCircle className="spin" size={22} />Загружаем рабочее пространство…</div> : !overview ? <EmptyState icon={<Database size={28} />} title="Нет соединения с данными">Не удалось загрузить проекты. Повторите обновление.</EmptyState> : projects.length === 0 ? <EmptyState icon={<FolderGit2 size={31} />} title="Пока нет проектов" action={<button className="button secondary" onClick={() => setCreateOpen(true)}><Plus size={16} />Добавить проект</button>}>Сохраните публичный GitHub URL и ветку, затем запустите проверку.</EmptyState> : shown.length === 0 ? <div className="simple-empty">Проекты по этому запросу не найдены.</div> : <div className="project-list">{shown.map(project => <button className="project-row" key={project.id} onClick={() => go('projects/' + project.id)}><span className="project-icon"><FolderGit2 size={20} /></span><span className="project-main"><strong>{project.name}</strong><small>{project.repositories[0]?.url.replace('https://github.com/', '') || 'Репозиторий пока не добавлен'}</small></span><span className="project-branch"><GitBranch size={13} />{project.repositories[0]?.default_branch || '—'}</span><span className="project-date">{date(project.created_at)}</span><ChevronRight size={16} /></button>)}</div>}
          </section>
          <section className="panel scanner-panel"><div className="panel-heading"><h2>Сканеры</h2><span className="tag neutral">3 подключено</span></div><div className="scanner-list">{tools.map(tool => <div className="scanner-row" key={tool.name}><div className="tool-icon"><tool.icon size={18} /></div><div><strong>{tool.name}</strong><small>{tool.role}</small></div><span className="tool-status"><Circle size={7} />Подключён</span></div>)}</div></section>
        </>}
        {view === 'project' && <ProjectDashboard key={route.id + pageRevision} id={route.id} onAdd={project => { setSelected(project); setRepositoryOpen(true); }} onStart={id => void startScan(id)} busy={!isReady || startingScan !== null} />}
        {view === 'findings' && <FindingsPage key={pageRevision} query={route.query} projects={projects} />}
        {view === 'finding' && <FindingDetail key={route.id + pageRevision} id={route.id} query={route.query} />}
        {view === 'activity' && <ScanHistory key={pageRevision} query={route.query} projects={projects} />}
        {view === 'system' && <>
          <section className="panel"><div className="panel-heading"><div><h2>Компоненты</h2><p>Размещены на Bult.ai</p></div></div><div className="service-grid">{[{ name: 'Приложение', desc: 'React + FastAPI', icon: LayoutDashboard, state: isReady ? 'Доступно' : 'Нет соединения', enabled: isReady }, { name: 'База данных', desc: 'PostgreSQL', icon: Database, state: isReady ? 'Подключена' : 'Нет соединения', enabled: isReady }, { name: 'Сканирование', desc: 'Gitleaks, Semgrep CE, Trivy', icon: ScanLine, state: scans.some(scan => scan.status === 'COMPLETED') ? 'Есть завершённые проверки' : 'Нет завершённых проверок', enabled: scans.some(scan => scan.status === 'COMPLETED') }].map(service => <div className="service-card" key={service.name}><service.icon size={22} /><h3>{service.name}</h3><p>{service.desc}</p><span className={`tag ${service.enabled ? 'mint' : 'neutral'}`}>{service.state}</span></div>)}</div><p className="system-note">Статус сканирования указан по истории запусков. Подробности каждого запуска доступны во вкладке «Сканирования».</p></section>
          <section className="panel system-details"><div className="panel-heading"><h2>Сведения о приложении</h2></div><dl className="system-facts"><div><dt>Версия</dt><dd>0.7.0</dd></div><div><dt>База данных</dt><dd>{readiness?.database || 'Недоступна'}</dd></div><div><dt>Версия схемы</dt><dd>{readiness?.schema_revision || '—'}</dd></div><div><dt>Окружение</dt><dd>{readiness?.environment === 'production' ? 'Рабочее' : readiness?.environment === 'development' ? 'Локальное' : '—'}</dd></div></dl><a className="text-button" href="/api/openapi.json" target="_blank" rel="noreferrer">Описание API<ExternalLink size={13} /></a></section>
        </>}
        <footer className="footer"><span><ShieldCheck size={14} />BultShield</span><span>Версия 0.7.0</span></footer>
      </main>
    </div>
    {createOpen && <ProjectForm onClose={() => setCreateOpen(false)} onSaved={project => void created(project)} />}
    {repositoryOpen && selected && <RepositoryForm project={selected} onClose={() => setRepositoryOpen(false)} onSaved={() => { setRepositoryOpen(false); setNotice('Репозиторий сохранён.'); setPageRevision(n => n + 1); void refresh(); }} />}
  </div>;
}
