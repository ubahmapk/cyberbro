from pydantic import BaseModel, model_serializer

"""Registry of report classes for serialization/deserialization."""
_REPORT_REGISTRY: dict[str, type] = {}


class BaseReport(BaseModel):
    success: bool = False
    error: str | None = None

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        _REPORT_REGISTRY[cls.__name__] = cls

    @classmethod
    def from_dict(cls, data: dict) -> "BaseReport":
        data = dict(data)  # avoid mutating caller's dict
        cls_name = data.pop("__cls__", None)
        klass = _REPORT_REGISTRY.get(cls_name, cls)
        return klass(**data)

    @model_serializer
    def __json__(self) -> dict:
        d = {name: getattr(self, name) for name in type(self).model_fields}
        d["__cls__"] = type(self).__name__
        return d

    def get(self, name: str, default: object = None) -> object:
        return getattr(self, name, default)
