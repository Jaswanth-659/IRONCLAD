"""
IRONCLAD Configuration Management.

Provides strongly typed configuration models and loading utilities supporting YAML
files, dictionary overrides, and environment defaults.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from ironclad.core.exceptions import ConfigurationError


@dataclass
class IngestionConfig:
    backend: str = "scapy"
    batch_size: int = 1000
    max_packets: Optional[int] = None
    bpf_filter: str = ""

    def validate(self) -> None:
        if self.backend not in ("scapy", "pyshark"):
            raise ConfigurationError(
                f"Invalid ingestion backend '{self.backend}'. Must be 'scapy' or 'pyshark'."
            )
        if self.batch_size <= 0:
            raise ConfigurationError("batch_size must be positive integer.")
        if self.max_packets is not None and self.max_packets <= 0:
            raise ConfigurationError("max_packets must be positive integer if specified.")


@dataclass
class ParsingConfig:
    parse_payload: bool = True
    payload_preview_bytes: int = 64
    compute_packet_entropy: bool = True

    def validate(self) -> None:
        if self.payload_preview_bytes < 0:
            raise ConfigurationError("payload_preview_bytes cannot be negative.")


@dataclass
class FeatureConfig:
    bidirectional_flows: bool = True
    flow_timeout_seconds: float = 120.0
    entropy_block_size: int = 256

    def validate(self) -> None:
        if self.flow_timeout_seconds <= 0:
            raise ConfigurationError("flow_timeout_seconds must be > 0.")
        if self.entropy_block_size <= 0:
            raise ConfigurationError("entropy_block_size must be > 0.")


@dataclass
class AnomalyConfig:
    contamination: float = 0.05
    n_estimators: int = 100
    z_score_threshold: float = 3.0
    iqr_multiplier: float = 1.5
    random_state: int = 42

    def validate(self) -> None:
        if not (0.0 < self.contamination <= 0.5):
            raise ConfigurationError("contamination must be in (0.0, 0.5].")
        if self.n_estimators <= 0:
            raise ConfigurationError("n_estimators must be positive integer.")
        if self.z_score_threshold <= 0:
            raise ConfigurationError("z_score_threshold must be positive float.")
        if self.iqr_multiplier <= 0:
            raise ConfigurationError("iqr_multiplier must be positive float.")


@dataclass
class GraphConfig:
    calculate_pagerank: bool = True
    calculate_clustering: bool = True
    fanout_threshold: float = 10.0

    def validate(self) -> None:
        if self.fanout_threshold <= 0:
            raise ConfigurationError("fanout_threshold must be > 0.")


@dataclass
class RiskConfig:
    anomaly_weight: float = 0.40
    graph_weight: float = 0.30
    rule_weight: float = 0.30
    severity_thresholds: Dict[str, float] = field(
        default_factory=lambda: {
            "critical": 80.0,
            "high": 60.0,
            "medium": 35.0,
            "low": 0.0,
        }
    )

    def validate(self) -> None:
        total = self.anomaly_weight + self.graph_weight + self.rule_weight
        if abs(total - 1.0) > 1e-4:
            raise ConfigurationError(
                f"Risk weights must sum to 1.0; current sum is {total:.4f}"
            )


@dataclass
class LoggingConfig:
    level: str = "INFO"
    log_file: Optional[str] = "logs/ironclad.log"
    enable_console: bool = True

    def validate(self) -> None:
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.level.upper() not in valid_levels:
            raise ConfigurationError(f"Invalid logging level '{self.level}'. Must be one of {valid_levels}")


@dataclass
class EngineConfig:
    name: str = "IRONCLAD-Phase1-Core"
    version: str = "1.0.0"
    ingestion: IngestionConfig = field(default_factory=IngestionConfig)
    parsing: ParsingConfig = field(default_factory=ParsingConfig)
    features: FeatureConfig = field(default_factory=FeatureConfig)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    graph: GraphConfig = field(default_factory=GraphConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    def validate(self) -> None:
        self.ingestion.validate()
        self.parsing.validate()
        self.features.validate()
        self.anomaly.validate()
        self.graph.validate()
        self.risk.validate()
        self.logging.validate()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EngineConfig:
        engine_dict = data.get("engine", {})
        name = engine_dict.get("name", "IRONCLAD-Phase1-Core")
        version = engine_dict.get("version", "1.0.0")

        ingestion_data = data.get("ingestion", {})
        parsing_data = data.get("parsing", {})
        feature_data = data.get("features", {})
        anomaly_data = data.get("anomaly", {})
        graph_data = data.get("graph", {})
        risk_data = data.get("risk", {})
        logging_data = data.get("logging", {})

        config = cls(
            name=name,
            version=version,
            ingestion=IngestionConfig(**ingestion_data) if ingestion_data else IngestionConfig(),
            parsing=ParsingConfig(**parsing_data) if parsing_data else ParsingConfig(),
            features=FeatureConfig(**feature_data) if feature_data else FeatureConfig(),
            anomaly=AnomalyConfig(**anomaly_data) if anomaly_data else AnomalyConfig(),
            graph=GraphConfig(**graph_data) if graph_data else GraphConfig(),
            risk=RiskConfig(**risk_data) if risk_data else RiskConfig(),
            logging=LoggingConfig(**logging_data) if logging_data else LoggingConfig(),
        )
        config.validate()
        return config

    @classmethod
    def from_yaml(cls, path: str | Path) -> EngineConfig:
        file_path = Path(path)
        if not file_path.exists():
            raise ConfigurationError(f"Configuration file not found: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f) or {}
            return cls.from_dict(content)
        except yaml.YAMLError as e:
            raise ConfigurationError(f"YAML parsing error in {file_path}: {e}") from e

    @classmethod
    def default(cls) -> EngineConfig:
        default_yaml = Path(__file__).parent / "default_config.yaml"
        if default_yaml.exists():
            return cls.from_yaml(default_yaml)
        config = cls()
        config.validate()
        return config

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_yaml(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)
