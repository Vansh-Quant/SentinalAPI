"""Project endpoints — ownership enforced on every access."""

import logging
import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession
from app.models.project import Project
from app.schemas.project import ProjectCreate, ProjectList, ProjectOut

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectOut, status_code=201)
def create_project(payload: ProjectCreate, user: CurrentUser, db: DbSession) -> Project:
    project = Project(
        owner_id=user.id,
        name=payload.name.strip(),
        description=payload.description,
        base_url=payload.base_url.strip(),
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    logger.info("project created: %s by %s", project.id, user.email)
    return project


@router.get("", response_model=ProjectList)
def list_projects(user: CurrentUser, db: DbSession) -> ProjectList:
    projects = db.execute(
        select(Project).where(Project.owner_id == user.id).order_by(Project.created_at.desc())
    ).scalars().all()
    return ProjectList(total=len(projects), items=list(projects))


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: str, user: CurrentUser, db: DbSession) -> Project:
    try:
        pid = uuid.UUID(project_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Project not found")
    project = db.get(Project, pid)
    if project is None or project.owner_id != user.id:
        # Same response for missing and foreign projects: don't leak existence.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project
