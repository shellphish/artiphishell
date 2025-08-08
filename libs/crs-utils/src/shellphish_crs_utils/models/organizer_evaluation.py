from enum import Enum
import hashlib
from typing import Optional
from pydantic import BaseModel, Field
from shellphish_crs_utils.models import ShellphishBaseModel

class SignificanceEnum(Enum):
    """
    Enum for significance levels.
    """
    NoSignificantCrashRecognized = 0
    RecognizedSanitizerCrash = 211
    RecognizedNonSanitizerNotableCrash = 212
    RecognizedSanitizerSignatureDespite0ReturnCode = 213
    RecognizedErrorInReproducing = 214

class OrganizerCrashEvaluation(ShellphishBaseModel):
    """
    Model for the organizer's crash evaluation results.
    """
    code_label: str
    significance: SignificanceEnum
    significance_message: str
    crash_state: str
    instrumentation_key: Optional[str] = Field(
        default=None,
        description="The instrumentation key for the crash, if available.",
    )

    def plaintext_identifier(self) -> str:
        """
        Generate a unique plaintext identifier for the crash evaluation.
        :return: A string identifier based on the evaluation content.
        """
        return f"{self.code_label}--{self.significance.value}--{self.significance_message}--{self.crash_state}--{self.instrumentation_key or ''}"
    def hashed_identifier(self) -> str:
        """
        Generate a unique identifier for the crash evaluation based on its content.
        :return: A SHA256 hash of the evaluation content.
        """
        return hashlib.sha256(self.plaintext_identifier().encode('utf-8')).hexdigest()
