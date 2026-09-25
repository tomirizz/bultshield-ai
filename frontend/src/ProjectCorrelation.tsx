import { useEffect, useState } from 'react';
import { request } from './api';
import type { Finding } from './api';

type Group = { id: string; title: string; ai_interpretation: string; verification: string; scanner_evidence: Finding[] };
type Run = { id: string; status: string; model: string; total_findings: number; analysed_findings: number; stale: boolean; error_message: string | null; groups: Group[] };
export function ProjectCorrelation({ projectId }: { projectId: string }) {
  const [run, setRun] = useState<Run | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    let live = true; let timer: number;
    async function refresh() {
      try {
        const [status, result] = await Promise.all([request<{ enabled: boolean }>('/api/ai-status'), request<Run | null>(`/api/projects/${projectId}/correlation`)]);
        if (live) { setEnabled(status.enabled); setRun(result); setLoaded(true); }
      } catch (e) { if (live) setError(e instanceof Error ? e.message : 'Не удалось загрузить группы'); }
      if (live) timer = window.setTimeout(refresh, 5000);
    }
    void refresh(); return () => { live = false; window.clearTimeout(timer); };
  }, [projectId]);
  const pending = run?.status === 'PENDING' || run?.status === 'RUNNING';
  async function start() {
    setBusy(true); setError('');
    try { setRun(await request<Run>(`/api/projects/${projectId}/correlation`, { method: 'POST' })); }
    catch (e) { setError(e instanceof Error ? e.message : 'Не удалось запустить корреляцию'); }
    finally { setBusy(false); }
  }
  return <section className="panel ai-explanation" aria-label="Связанные проблемы">
    <div className="panel-heading"><div><h2>Связанные проблемы</h2><p>Возможные общие причины находок одного проекта</p></div>
      <button className="button secondary" disabled={!enabled || busy || pending || (run?.status === 'COMPLETED' && !run.stale)} onClick={() => void start()}>{pending ? 'Анализ выполняется…' : run?.stale ? 'Обновить связи' : run?.status === 'FAILED' ? 'Повторить анализ' : 'Найти связанные проблемы'}</button></div>
    <div className="ai-content">
      {error && <p className="alert error" role="alert">{error}</p>}
      {loaded && !enabled && <p>Для корреляции необходимо подключить модель на Bult.ai.</p>}
      <p className="summary-note">Анализируются последние успешные проверки. Модель получает безопасные описания и обезличенные связи файлов и пакетов; исходный код и секреты не передаются.</p>
      {pending && <p role="status">{run?.status === 'PENDING' ? 'Задание в очереди.' : 'Модель ищет возможные связи.'} Результат сохранится после завершения.</p>}
      {run?.error_message && <p className="alert error">{run.error_message}</p>}
      {run?.stale && <p className="summary-note">Появились новые результаты сканирования. Эти группы относятся к предыдущим проверкам.</p>}
      {run && <p className="summary-note">Находок в анализе: {run.analysed_findings} из {run.total_findings}. {run.total_findings > run.analysed_findings && 'Обработана только часть находок: ограничение одного анализа — 12.'}</p>}
      {run?.status === 'COMPLETED' && <><p className="ai-disclosure">AI interpretation · модель {run.model}, Bult.ai. Связи являются гипотезами и требуют проверки разработчиком.</p>
        {!run.groups.length && <p>Модель не предложила связанных групп. Это не доказывает отсутствие связей или уязвимостей.</p>}
        {run.groups.map(group => <article key={group.id} className="correlation-group"><h3>{group.title}</h3><h4>AI interpretation · гипотеза</h4><p>{group.ai_interpretation}</p><p><strong>Что проверить:</strong> {group.verification}</p>
          <h4>Scanner evidence · результаты сканеров</h4>{group.scanner_evidence.map(f => <div className="correlation-evidence" key={f.id}><a href={`#/findings/${f.id}`}>{f.title} →</a><p><strong>{f.scanner}</strong> · {f.severity} · {f.file || 'Файл не указан'}{f.line_start ? `:${f.line_start}` : ''}</p><p>Правило: {f.rule_id}{f.cve ? ` · ${f.cve}` : ''}{f.cwe ? ` · ${f.cwe}` : ''}</p><pre>{f.evidence || 'Evidence не предоставлен сканером.'}</pre></div>)}
        </article>)}
      </>}
    </div>
  </section>;
}
