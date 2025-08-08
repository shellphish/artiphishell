from typing import Optional
from pydantic import Field
from shellphish_crs_utils.models.base import ShellphishBaseModel

class PDTNodeInfo(ShellphishBaseModel):
    ip: Optional[str] = Field(default=None, description='The IP address that should be used to connect to the node. This can be different ' +
                    'from the node_ip field as that is a public IP while this might be the cluster-internal one.')
    self: bool = Field(description='Indicates if this node is the same as the node that requested the node information.')
    node_ip: str = Field(description='The public IP address of the node.')
    name: str = Field(description='The name of the node. This is kubernetes pod names and should generally be consecutively numbered. Example names are: "node-0", "node-1", etc.')
