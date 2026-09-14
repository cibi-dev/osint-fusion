from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class OSINTDocument(BaseModel):
    id: str
    source: str
    title: str
    content: str
    timestamp: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class Entity(BaseModel):
    id: str
    type: str # PERSON, DOMAIN, IP, WALLET, ORG
    value: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class Relation(BaseModel):
    source_id: str
    target_id: str
    relation_type: str
    weight: float = 1.0
