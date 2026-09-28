import { useEffect, useState } from 'react';
import { request } from './api';

type Fix = { id: string; status: string; description: string; diff: string | null; file: string | null; base_sha: string; original: string | null; proposed: string | null; error_message: string | null; verification_scan_id: string | null; timeline: { status: string; at: string }[]; verification: { outcome?: string; before_matches?: number; after_matches?: number; before_total?: number; after_total?: number; note?: string } };
const names: Record<string, string> = { QUEUED: 'В очереди', GENERATING: 'Подготовка предложения', PROPOSED: 'Исправление предложено', APPROVED: 'Одобрено · в очереди', APPLIED: 'Применено в тестовой копии', RECHECKING: 'Повторная проверка', VERIFIED_FIXED: 'Исправление подтверждено · тестовая копия', STILL_DETECTED: 'Проблема сохраняется', FAILED: 'Проверка не завершена' };
export function FixReview({ findingId }: { findingId: string }) {
  const [fix, setFix] = useState<Fix | null>(null);
  const [supported, setSupported] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [enabled, setEnabled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [reviewed, setReviewed] = useState(false);
  const [branch, setBranch] = useState('');
  useEffect(() => {
    let live = true; let timer: number;
    async function refresh() {
      try {
        const [data, ai] = await Promise.all([request<{ supported: boolean; fix: Fix | null }>(`/api/findings/${findingId}/fix`), request<{ enabled: boolean }>('/api/ai-status')]);
        if (live) { setFix(data.fix); setSupported(data.supported); setEnabled(ai.enabled); setLoaded(true); }
      } catch (e) { if (live) setError(e instanceof Error ? e.message : 'Ошибка загрузки'); }
      if (live) timer = window.setTimeout(refresh, 4000);
    }
    void refresh(); return () => { live = false; window.clearTimeout(timer); };
  }, [findingId]);
  async function action(approve = false) {
    setBusy(true); setError('');
    try { setFix(await request<Fix>(approve ? `/api/fixes/${fix!.id}/approve` : `/api/findings/${findingId}/fix`, { method: 'POST' })); setReviewed(false); }
    catch (e) { setError(e instanceof Error ? e.message : 'Не удалось выполнить действие'); }
    finally { setBusy(false); }
  }
  async function createBranch() {
    setBusy(true); setError('');
    try { const result = await request<{ url: string }>(`/api/github/fixes/${fix!.id}/branch`, { method: 'POST' }); setBranch(result.url); }
    catch (e) { setError(e instanceof Error ? e.message : 'Не удалось создать ветку'); }
    finally { setBusy(false); }
  }
  async function reject() {
    setBusy(true); setError('');
    try { setFix(await request<Fix>(`/api/fixes/${fix!.id}/reject`, { method: 'POST' })); setReviewed(false); }
    catch (e) { setError(e instanceof Error ? e.message : 'Не удалось отклонить предложение'); }
    finally { setBusy(false); }
  }
  return <section className="panel ai-explanation"><div className="panel-heading"><div><h2>Исправление с помощью AI</h2><p>Предложение исправления и проверка сканером</p></div>{loaded && supported && (!fix || ['FAILED', 'STILL_DETECTED'].includes(fix.status)) && <button className="button primary" disabled={busy || !enabled} onClick={() => void action()}>Предложить исправление</button>}</div>
    <div className="ai-content">
      {error && <p className="alert error" role="alert">{error}</p>}
      {!loaded ? <p>Загрузка…</p> : !supported ? <p>Секреты и веб-находки исправляются вручную. Генератор работает с небольшими файлами кода, зависимостей и конфигурации.</p> : <p>Модель на Bult.ai получает находку и исходный файл до 4 КБ после проверки на секреты. Предложение требует вашего просмотра.</p>}
      <p className="ai-disclosure">Кнопка «Применить и проверить» запускает проверку в отдельной тестовой копии. Репозиторий не изменяется. Подтверждение означает, что сканер больше не находит эту проблему; работоспособность приложения нужно проверить отдельно.</p>
      {fix && <><p role="status"><strong>{names[fix.status] || fix.status}</strong> · коммит {fix.base_sha?.slice(0, 7)}</p>
        {fix.error_message && <p className="alert error">{fix.error_message}</p>}
        {fix.original !== null && <><p>{fix.file}</p><div className="fix-comparison"><div><h3>Исходный код</h3><pre>{fix.original}</pre></div><div><h3>Предложенный код</h3><pre>{fix.proposed}</pre></div></div><h3>Изменения</h3><pre>{fix.diff}</pre><h3>Пояснение AI</h3><p>{fix.description}</p></>}
        {fix.status === 'PROPOSED' && <><label className="fix-consent"><input type="checkbox" checked={reviewed} onChange={e => setReviewed(e.target.checked)} />Я просмотрел изменения и одобряю проверку во временной копии.</label><button className="button primary" disabled={busy || !reviewed} onClick={() => void action(true)}>Применить и проверить</button> <button className="button" disabled={busy} onClick={() => void reject()}>Отклонить предложение</button></>}
        {fix.verification.outcome && <><h3>До и после</h3>{fix.verification.outcome === 'INCONCLUSIVE' ? <p>Проверка не завершена. Исправление не подтверждено.</p> : <><p>Совпадений исходного правила: <strong>{fix.verification.before_matches} → {fix.verification.after_matches}</strong></p><p>Всего находок проверявшего сканера: {fix.verification.before_total} → {fix.verification.after_total}.</p><p>{fix.verification.note}</p></>}</>}
        {fix.status === 'VERIFIED_FIXED' && (branch ? <a className="text-button" href={branch} target="_blank" rel="noreferrer">Открыть ветку в GitHub ↗</a> : <button className="button secondary" disabled={busy} onClick={createBranch}>Создать ветку с исправлением</button>)}
        {fix.verification_scan_id && <a className="text-button" href={`#/findings?scan_id=${fix.verification_scan_id}&scope=all`}>Результаты повторной проверки →</a>}
        {!!fix.timeline.length && <div className="fix-timeline"><span>Обнаружено</span>{fix.timeline.map((entry, i) => <span key={i}> → {names[entry.status] || entry.status}</span>)}</div>}
      </>}
    </div>
  </section>;
}
