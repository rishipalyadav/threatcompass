from .llm01_prompt_injection import LLM01_PromptInjection
from .llm06_sensitive_disclosure import LLM06_SensitiveDisclosure
from .llm08_excessive_agency import LLM08_ExcessiveAgency
from .remaining_evaluators import (
    LLM02_InsecureOutput,
    LLM03_TrainingDataPoisoning,
    LLM04_ModelDoS,
    LLM05_SupplyChain,
    LLM07_InsecurePlugin,
    LLM09_Overreliance,
    LLM10_ModelTheft,
)

ALL_EVALUATORS = [
    LLM01_PromptInjection(),
    LLM02_InsecureOutput(),
    LLM03_TrainingDataPoisoning(),
    LLM04_ModelDoS(),
    LLM05_SupplyChain(),
    LLM06_SensitiveDisclosure(),
    LLM07_InsecurePlugin(),
    LLM08_ExcessiveAgency(),
    LLM09_Overreliance(),
    LLM10_ModelTheft(),
]
