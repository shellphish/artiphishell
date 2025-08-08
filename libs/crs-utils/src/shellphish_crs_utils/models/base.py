from pydantic import BaseModel, ConfigDict


class ShellphishBaseModel(BaseModel):
    # THIS IS CRITICAL, do not remove without checking with @clasm, @honululu or @Amy-B.
    # If you are overriding this, make sure to set extra='forbid'. But still check with us.

    model_config = ConfigDict(extra='forbid')