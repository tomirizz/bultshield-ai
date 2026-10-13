import assert from 'node:assert/strict';
import { test } from 'node:test';
import { request } from '../src/api.ts';

test('a stalled request releases the UI and warns that the job may already exist', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  t.mock.method(globalThis, 'fetch', (_path, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
  }));
  const pending = request('/api/checks', { method: 'POST' });
  const rejected = assert.rejects(pending, /задание могло быть принято/);
  t.mock.timers.tick(30000);
  await rejected;
});

test('server failure remains visible instead of being reported as success', async t => {
  t.mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify({ detail: 'Модель не подключена' }), { status: 409 }));
  await assert.rejects(request('/api/checks/test/explanations'), /Модель не подключена/);
});

test('successful jobs return their persistent identifier', async t => {
  t.mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify({ id: 'accepted-job' }), { status: 202 }));
  assert.deepEqual(await request('/api/checks'), { id: 'accepted-job' });
});
