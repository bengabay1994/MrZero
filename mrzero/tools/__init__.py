"""Tools module - Wrappers for external security tools."""

from mrzero.tools.base import BaseTool, DockerTool, ToolOutput
from mrzero.tools.sast import OpengrepTool, GitleaksTool, TrivyTool
from mrzero.tools.linguist import LinguistTool
from mrzero.tools.smart_contract import SlitherTool, MythrilTool
from mrzero.tools.binary import BinwalkTool, StringsTool, ROPgadgetTool
from mrzero.tools.code_analysis import CodeQLTool, JoernTool, TreeSitterTool
from mrzero.tools.additional_sast import InferTool, BearerTool, ApplicationInspectorTool
from mrzero.tools.dynamic_analysis import (
    PwntoolsTool,
    FridaTool,
    GDBTool,
    AFLTool,
    MetasploitTool,
    MSFVenomTool,
    WinDbgTool,
    WinAFLTool,
)

__all__ = [
    # Base
    "BaseTool",
    "DockerTool",
    "ToolOutput",
    # SAST
    "OpengrepTool",
    "GitleaksTool",
    "TrivyTool",
    # Language Detection
    "LinguistTool",
    # Additional SAST
    "InferTool",
    "BearerTool",
    "ApplicationInspectorTool",
    # Code Analysis
    "CodeQLTool",
    "JoernTool",
    "TreeSitterTool",
    # Smart Contract
    "SlitherTool",
    "MythrilTool",
    # Binary
    "BinwalkTool",
    "StringsTool",
    "ROPgadgetTool",
    # Dynamic Analysis
    "PwntoolsTool",
    "FridaTool",
    "GDBTool",
    "AFLTool",
    "MetasploitTool",
    "MSFVenomTool",
    "WinDbgTool",
    "WinAFLTool",
]
