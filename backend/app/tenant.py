"""Request sessions always carry owner filters, including aggregates and child records."""
from sqlalchemy import event, select
from sqlalchemy.orm import with_loader_criteria

from .models import AgentRun, AIAnalysis, AuditEvent, CorrelationRun, Finding, Fix, Project, Repository, Rescan, Scan, ScanJob, SecurityIssueGroup, WebTarget


def isolate(session, owner_id):
    session.info['owner_id'] = owner_id
    # Core table subqueries deliberately avoid recursive ORM loader criteria.
    projects = select(Project.__table__.c.id).where(Project.__table__.c.owner_id == owner_id)
    findings = select(Finding.__table__.c.id).where(Finding.__table__.c.project_id.in_(projects))
    scans = select(Scan.__table__.c.id).where(Scan.__table__.c.project_id.in_(projects))
    runs = select(CorrelationRun.__table__.c.id).where(CorrelationRun.__table__.c.project_id.in_(projects))
    filters = [(Project, Project.owner_id == owner_id), (AuditEvent, AuditEvent.user_id == owner_id)]
    filters += [(model, model.project_id.in_(projects)) for model in (Repository, Scan, Finding, Rescan, CorrelationRun, WebTarget, AgentRun)]
    filters += [(model, model.finding_id.in_(findings)) for model in (AIAnalysis, Fix)]
    filters += [(ScanJob, ScanJob.scan_id.in_(scans)), (SecurityIssueGroup, SecurityIssueGroup.run_id.in_(runs))]

    @event.listens_for(session, 'do_orm_execute')
    def scope(execution):
        if execution.is_select or execution.is_update or execution.is_delete:
            execution.statement = execution.statement.options(*[
                with_loader_criteria(model, condition, include_aliases=True) for model, condition in filters])
