import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { request } from './api';
export function AuthGate({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<{ enabled: boolean; configured: boolean; authenticated: boolean }>();
  const [error, setError] = useState('');
  useEffect(() => { void request<{ enabled: boolean; configured: boolean; authenticated: boolean }>('/api/auth/status').then(setStatus).catch(e => setError(e.message)); }, []);
  if (status?.authenticated) return <>{children}{status.enabled && <form action="/api/auth/logout" method="post" className="session-exit"><button className="button secondary">Выйти</button></form>}</>;
  return <main className="login-page"><section className="panel"><h1>BultShield</h1><p>Проверки безопасности ваших проектов</p>{error ? <p role="alert">{error}</p> : !status ? <p>Проверка подключения…</p> : status.configured ? <a className="button primary" href="/api/auth/github">Войти через GitHub</a> : <p>Администратор завершает настройку входа через GitHub.</p>}</section></main>;
}
