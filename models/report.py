from __future__ import annotations

from pydantic import BaseModel, SerializerFunctionWrapHandler, model_serializer

"""Registry of report classes for serialization/deserialization."""
_REPORT_REGISTRY: dict[str, type] = {}


class BaseReport(BaseModel):
    # Easy check to see if the engine was successful
    # If false, show the error
    # If true, continue processing the sub-class's data
    success: bool = False
    error: str | None = None

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        _REPORT_REGISTRY[cls.__name__] = cls

    @classmethod
    def from_dict(cls, data: dict) -> BaseReport:
        data = dict(data)  # avoid mutating caller's dict
        cls_name = data.pop("__cls__", None)
        klass = _REPORT_REGISTRY.get(cls_name, cls)
        return klass(**data)

    @model_serializer(mode="wrap")
    def __json__(self, handler: SerializerFunctionWrapHandler) -> dict:
        d = handler(self)
        d["__cls__"] = type(self).__name__
        return d

    def get(self, name: str, default: object = None) -> object:
        return getattr(self, name, default)
