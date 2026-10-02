from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Severity(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SEVERITY_UNSPECIFIED: _ClassVar[Severity]
    SEVERITY_CRITICAL: _ClassVar[Severity]
    SEVERITY_HIGH: _ClassVar[Severity]
    SEVERITY_MEDIUM: _ClassVar[Severity]
    SEVERITY_LOW: _ClassVar[Severity]
    SEVERITY_INFO: _ClassVar[Severity]

class ScannerKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SCANNER_KIND_UNSPECIFIED: _ClassVar[ScannerKind]
    SCANNER_KIND_FIXTURE: _ClassVar[ScannerKind]
    SCANNER_KIND_SEMGREP: _ClassVar[ScannerKind]
    SCANNER_KIND_ZAP: _ClassVar[ScannerKind]
    SCANNER_KIND_DEPENDENCY: _ClassVar[ScannerKind]

class Confidence(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CONFIDENCE_UNSPECIFIED: _ClassVar[Confidence]
    CONFIDENCE_LOW: _ClassVar[Confidence]
    CONFIDENCE_MEDIUM: _ClassVar[Confidence]
    CONFIDENCE_HIGH: _ClassVar[Confidence]
SEVERITY_UNSPECIFIED: Severity
SEVERITY_CRITICAL: Severity
SEVERITY_HIGH: Severity
SEVERITY_MEDIUM: Severity
SEVERITY_LOW: Severity
SEVERITY_INFO: Severity
SCANNER_KIND_UNSPECIFIED: ScannerKind
SCANNER_KIND_FIXTURE: ScannerKind
SCANNER_KIND_SEMGREP: ScannerKind
SCANNER_KIND_ZAP: ScannerKind
SCANNER_KIND_DEPENDENCY: ScannerKind
CONFIDENCE_UNSPECIFIED: Confidence
CONFIDENCE_LOW: Confidence
CONFIDENCE_MEDIUM: Confidence
CONFIDENCE_HIGH: Confidence

class Finding(_message.Message):
    __slots__ = ("fingerprint", "rule_id", "title", "description", "severity", "confidence", "scanner_kind", "target", "file_path", "start_line", "end_line", "snippet", "cwe_ids", "cve_ids", "raw_payload_json", "detected_at")
    FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    RULE_ID_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    SCANNER_KIND_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    FILE_PATH_FIELD_NUMBER: _ClassVar[int]
    START_LINE_FIELD_NUMBER: _ClassVar[int]
    END_LINE_FIELD_NUMBER: _ClassVar[int]
    SNIPPET_FIELD_NUMBER: _ClassVar[int]
    CWE_IDS_FIELD_NUMBER: _ClassVar[int]
    CVE_IDS_FIELD_NUMBER: _ClassVar[int]
    RAW_PAYLOAD_JSON_FIELD_NUMBER: _ClassVar[int]
    DETECTED_AT_FIELD_NUMBER: _ClassVar[int]
    fingerprint: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    scanner_kind: ScannerKind
    target: str
    file_path: str
    start_line: int
    end_line: int
    snippet: str
    cwe_ids: _containers.RepeatedScalarFieldContainer[str]
    cve_ids: _containers.RepeatedScalarFieldContainer[str]
    raw_payload_json: str
    detected_at: _timestamp_pb2.Timestamp
    def __init__(self, fingerprint: _Optional[str] = ..., rule_id: _Optional[str] = ..., title: _Optional[str] = ..., description: _Optional[str] = ..., severity: _Optional[_Union[Severity, str]] = ..., confidence: _Optional[_Union[Confidence, str]] = ..., scanner_kind: _Optional[_Union[ScannerKind, str]] = ..., target: _Optional[str] = ..., file_path: _Optional[str] = ..., start_line: _Optional[int] = ..., end_line: _Optional[int] = ..., snippet: _Optional[str] = ..., cwe_ids: _Optional[_Iterable[str]] = ..., cve_ids: _Optional[_Iterable[str]] = ..., raw_payload_json: _Optional[str] = ..., detected_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class SeverityCounts(_message.Message):
    __slots__ = ("critical", "high", "medium", "low", "info", "total")
    CRITICAL_FIELD_NUMBER: _ClassVar[int]
    HIGH_FIELD_NUMBER: _ClassVar[int]
    MEDIUM_FIELD_NUMBER: _ClassVar[int]
    LOW_FIELD_NUMBER: _ClassVar[int]
    INFO_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    critical: int
    high: int
    medium: int
    low: int
    info: int
    total: int
    def __init__(self, critical: _Optional[int] = ..., high: _Optional[int] = ..., medium: _Optional[int] = ..., low: _Optional[int] = ..., info: _Optional[int] = ..., total: _Optional[int] = ...) -> None: ...

class ScanRequest(_message.Message):
    __slots__ = ("target", "scanners", "min_severity", "correlation_id")
    TARGET_FIELD_NUMBER: _ClassVar[int]
    SCANNERS_FIELD_NUMBER: _ClassVar[int]
    MIN_SEVERITY_FIELD_NUMBER: _ClassVar[int]
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    target: str
    scanners: _containers.RepeatedScalarFieldContainer[ScannerKind]
    min_severity: Severity
    correlation_id: str
    def __init__(self, target: _Optional[str] = ..., scanners: _Optional[_Iterable[_Union[ScannerKind, str]]] = ..., min_severity: _Optional[_Union[Severity, str]] = ..., correlation_id: _Optional[str] = ...) -> None: ...

class ScanResponse(_message.Message):
    __slots__ = ("scan_id", "scanner_kind", "target", "findings", "counts", "started_at", "duration_ms", "correlation_id", "error")
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    SCANNER_KIND_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    FINDINGS_FIELD_NUMBER: _ClassVar[int]
    COUNTS_FIELD_NUMBER: _ClassVar[int]
    STARTED_AT_FIELD_NUMBER: _ClassVar[int]
    DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    scan_id: str
    scanner_kind: ScannerKind
    target: str
    findings: _containers.RepeatedCompositeFieldContainer[Finding]
    counts: SeverityCounts
    started_at: _timestamp_pb2.Timestamp
    duration_ms: int
    correlation_id: str
    error: str
    def __init__(self, scan_id: _Optional[str] = ..., scanner_kind: _Optional[_Union[ScannerKind, str]] = ..., target: _Optional[str] = ..., findings: _Optional[_Iterable[_Union[Finding, _Mapping]]] = ..., counts: _Optional[_Union[SeverityCounts, _Mapping]] = ..., started_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., duration_ms: _Optional[int] = ..., correlation_id: _Optional[str] = ..., error: _Optional[str] = ...) -> None: ...

class HealthRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HealthResponse(_message.Message):
    __slots__ = ("healthy", "version", "available_scanners", "fixture_targets")
    HEALTHY_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    AVAILABLE_SCANNERS_FIELD_NUMBER: _ClassVar[int]
    FIXTURE_TARGETS_FIELD_NUMBER: _ClassVar[int]
    healthy: bool
    version: str
    available_scanners: _containers.RepeatedScalarFieldContainer[ScannerKind]
    fixture_targets: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, healthy: bool = ..., version: _Optional[str] = ..., available_scanners: _Optional[_Iterable[_Union[ScannerKind, str]]] = ..., fixture_targets: _Optional[_Iterable[str]] = ...) -> None: ...
