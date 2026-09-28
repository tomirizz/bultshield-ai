import { useState } from 'react';
import type { Project } from './api';
import { SecurityReview } from './SecurityReview';
import { SecurityAgent } from './SecurityAgent';
import { ProjectCorrelation } from './ProjectCorrelation';
import { SecurityHistory } from './SecurityHistory';
export function ReviewPage({ projects }: { projects: Project[] }) {
  const [selected, setSelected] = useState(new URLSearchParams(window.location.hash.split('?')[1] || '').get('project_id') || ''); const id = projects.some(p => p.id === selected) ? selected : projects[0]?.id;
  if (!id) return <p className="detail-empty">Добавьте проект и выполните первую проверку.</p>;
  return <div className="security-page"><label className="filter-label">Проект<select value={id} onChange={e => { setSelected(e.target.value); window.location.hash = '/review?project_id=' + e.target.value; }}>{projects.map(p => <option value={p.id} key={p.id}>{p.name}</option>)}</select></label><SecurityReview key={'review-' + id} projectId={id} /><ProjectCorrelation key={'groups-' + id} projectId={id} /><SecurityAgent key={'agent-' + id} projectId={id} /><SecurityHistory key={'history-' + id} projectId={id} /></div>;
}
