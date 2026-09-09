import uuid
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from backend.database import get_db
from backend.models import ScanConfig

router = APIRouter(prefix="/api/configs", tags=["configs"])


def serialize_uuid(val) -> str:
    if val is None:
        return ""
    if isinstance(val, uuid.UUID):
        return str(val)
    return str(val)


def serialize_datetime(val) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)


class ConfigCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256, description="Name for the scan configuration")
    config_json: dict = Field(default_factory=dict, description="Scan configuration parameters")
    is_default: bool = Field(default=False, description="Mark this config as the default")


class ConfigUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    config_json: Optional[dict] = None
    is_default: Optional[bool] = None


class ConfigSummary(BaseModel):
    id: str
    name: str
    config_json: dict
    is_default: bool
    created_at: str


@router.get("", response_model=List[ConfigSummary])
async def list_configs(
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanConfig).order_by(ScanConfig.created_at.desc())
    )
    configs = result.scalars().all()

    return [
        ConfigSummary(
            id=serialize_uuid(c.id),
            name=c.name,
            config_json=c.config_json or {},
            is_default=c.is_default,
            created_at=serialize_datetime(c.created_at),
        )
        for c in configs
    ]


@router.post("", response_model=ConfigSummary, status_code=201)
async def create_config(
    config_data: ConfigCreate,
    db: AsyncSession = Depends(get_db),
):
    if config_data.is_default:
        await _unset_existing_default(db)

    new_config = ScanConfig(
        id=uuid.uuid4(),
        name=config_data.name,
        config_json=config_data.config_json,
        is_default=config_data.is_default,
        created_at=datetime.utcnow(),
    )

    db.add(new_config)
    await db.commit()
    await db.refresh(new_config)

    return ConfigSummary(
        id=serialize_uuid(new_config.id),
        name=new_config.name,
        config_json=new_config.config_json or {},
        is_default=new_config.is_default,
        created_at=serialize_datetime(new_config.created_at),
    )


@router.put("/{config_id}", response_model=ConfigSummary)
async def update_config(
    config_id: str,
    config_data: ConfigUpdate,
    db: AsyncSession = Depends(get_db),
):
    try:
        config_uuid = uuid.UUID(config_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid config ID format")

    result = await db.execute(
        select(ScanConfig).where(ScanConfig.id == config_uuid)
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")

    if config_data.name is not None:
        config.name = config_data.name

    if config_data.config_json is not None:
        config.config_json = config_data.config_json

    if config_data.is_default is not None:
        if config_data.is_default:
            await _unset_existing_default(db)
        config.is_default = config_data.is_default

    await db.commit()
    await db.refresh(config)

    return ConfigSummary(
        id=serialize_uuid(config.id),
        name=config.name,
        config_json=config.config_json or {},
        is_default=config.is_default,
        created_at=serialize_datetime(config.created_at),
    )


@router.delete("/{config_id}", status_code=204)
async def delete_config(
    config_id: str,
    db: AsyncSession = Depends(get_db),
):
    try:
        config_uuid = uuid.UUID(config_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid config ID format")

    result = await db.execute(
        select(ScanConfig).where(ScanConfig.id == config_uuid)
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")

    await db.execute(
        delete(ScanConfig).where(ScanConfig.id == config_uuid)
    )
    await db.commit()


async def _unset_existing_default(db: AsyncSession):
    result = await db.execute(
        select(ScanConfig).where(ScanConfig.is_default == True)
    )
    existing_defaults = result.scalars().all()
    for existing in existing_defaults:
        existing.is_default = False
    if existing_defaults:
        await db.flush()
