from .anti_analysis_detection import AntiAnalysisDetection
from .call_analysis import CallAnalysis
from .cc_domain_detection import CCDomainDetection
from .code_injection_detection import CodeInjectionDetection
from .disassembly import Disassembly
from .dropper import Dropper
from .external_cnc import ExternalCnC
from .file_exfiltration_detection import FileExfiltrationDetection
from .flag_finder import FlagFinder
from .key_spying import KeySpying
from .persistence import Persistence
from .procedure_analysis import ProcedureAnalysis
from .screen_spying import ScreenSpying

all_plugins = [
    AntiAnalysisDetection,
    CallAnalysis,
    CCDomainDetection,
    CodeInjectionDetection,
    Dropper,
    ExternalCnC,
    FileExfiltrationDetection,
    KeySpying,
    Persistence,
    ProcedureAnalysis,
    ScreenSpying,
]
