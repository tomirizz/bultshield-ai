import { useEffect, useState } from 'react';
import { request } from './api';

type Result = { explanation: string; risk: string; checks: string[]; recommended_fix: string; code_example: string; remediation_steps: string[] };
type Analysis = { id: string; status: string; model: string; result: Result | null; error_message: string | null };
export function AIExplanation({ findingId }: { findingId: string }) {
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    let live = true; let timer: number;
    async function refresh() {
      try {
        const [status, result] = await Promise.all([
          request<{ enabled: boolean }>('/api/ai-status'),
          request<Analysis | null>(`/api/findings/${findingId}/analysis`),
        ]);
        if (live) { setEnabled(status.enabled); setAnalysis(result); setLoaded(true); setError(''); }
      } catch (e) { if (live) { setLoaded(true); setError(e instanceof Error ? e.message : 'Не удалось загрузить анализ'); } }
      if (live) timer = window.setTimeout(refresh, 4000);
    }
    void refresh();
    return () => { live = false; window.clearTimeout(timer); };
  }, [findingId]);
  const pending = analysis?.status === 'PENDING' || analysis?.status === 'RUNNING';
  async function start() {
    setBusy(true); setError('');
    try { setAnalysis(await request<Analysis>(`/api/findings/${findingId}/analysis`, { method: 'POST' })); }
    catch (e) { setError(e instanceof Error ? e.message : 'Не удалось запустить анализ'); }
    finally { setBusy(false); }
  }
  const result = analysis?.status === 'COMPLETED' ? analysis.result : null;
  return <section className="panel ai-explanation" aria-label="AI Explanation">
    <div className="panel-heading"><div><h2>AI Explanation</h2><p>Объяснение и рекомендации по результату сканера</p></div>
      {!result && <button className="button primary" disabled={!loaded || !enabled || busy || pending} onClick={() => void start()}>{busy ? 'Добавляем…' : pending ? 'Анализ выполняется…' : analysis?.status === 'FAILED' ? 'Повторить анализ' : 'Объяснить находку'}</button>}
    </div>
    <div className="ai-content">
      {error && <p className="alert error" role="alert">{error}</p>}
      {!loaded ? <p>Загрузка…</p> : !enabled && !result ? <p>Модель пока не подключена. Результаты сканеров доступны выше.</p> : null}
      {pending && <p role="status">{analysis?.status === 'PENDING' ? 'Задание в очереди.' : 'Модель готовит объяснение.'} Это может занять несколько минут. Можно закрыть страницу — результат сохранится.</p>}
      {analysis?.status === 'FAILED' && <p className="alert error" role="status">{analysis.error_message || 'Не удалось завершить анализ.'} Результат сканирования сохранён.</p>}
      {!result && !pending && enabled && <p>Модель получает тип проблемы и безопасные сведения о находке. Содержимое файлов и секреты не передаются.</p>}
      {result && <><p className="ai-disclosure">Сгенерировано моделью {analysis?.model} на Bult.ai. Это рекомендация, требующая проверки разработчиком. Файлы проекта не изменены.</p>
        <h3>Что найдено</h3><p>{result.explanation}</p>
        <h3>Почему это потенциально опасно</h3><p>{result.risk}</p>
        <h3>Где находится</h3><p>Файл и строка указаны в карточке находки выше. Модель не получает содержимое исходного файла.</p>
        <h3>Что проверить</h3><ul>{result.checks.map((step, i) => <li key={i}>{step}</li>)}</ul>
        <h3>Recommended Fix</h3><p>{result.recommended_fix}</p>
        <h3>Пример исправления</h3><p className="summary-note">Иллюстративный пример. Адаптируйте его к коду и зависимостям проекта.</p><pre>{result.code_example}</pre>
        <h3>Шаги исправления · AI-generated</h3><ol>{result.remediation_steps.map((step, i) => <li key={i}>{step}</li>)}</ol>
      </>}
    </div>
  </section>;
}
