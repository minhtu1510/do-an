"""OPC UA Protocol Client"""

from typing import Optional, Dict, Any, List
try:
    from opcua import Client as OPCClient
    OPCUA_AVAILABLE = True
except ImportError:
    OPCUA_AVAILABLE = False
    OPCClient = None

from icsscout.core.protocols.base import BaseProtocolClient, ConnectionState
from icsscout.domain import Target, Result
from icsscout.utils.errors import ConnectionError as ICSConnectionError, ProtocolError
from icsscout.utils.logger import get_logger


class OPCUAClient(BaseProtocolClient):
    """
    OPC UA Protocol Client

    Universal protocol supported by many vendors:
    - Siemens
    - Schneider Electric
    - ABB
    - Beckhoff
    - B&R Automation
    - Rockwell Automation
    - And many more...

    Requires: pip install opcua
    """

    def __init__(self, target: Target):
        """
        Initialize OPC UA client

        Args:
            target: Target device with IP, port
        """
        super().__init__(target)

        if not OPCUA_AVAILABLE:
            raise ImportError(
                "OPC UA support requires 'opcua' library. "
                "Install it with: pip install opcua"
            )

        self.client: Optional[OPCClient] = None
        self.logger = get_logger('OPCUAClient')
        self.port = target.port or 4840  # Default OPC UA port

    def connect(self) -> Result:
        """
        Connect to OPC UA server

        Returns:
            Result indicating connection success/failure
        """
        try:
            self.state = ConnectionState.CONNECTING
            url = f"opc.tcp://{self.target.device.ip}:{self.port}"
            self.logger.info(f"Connecting to {url}")

            # Create OPC UA client
            self.client = OPCClient(url)

            # Set timeout
            self.client.session_timeout = 10000  # 10 seconds

            # Connect
            self.client.connect()

            self.state = ConnectionState.CONNECTED
            from datetime import datetime
            self.connected_at = datetime.now()

            self.logger.info(f"Connected successfully to {url}")
            return Result.ok("Connected successfully")

        except Exception as e:
            self.state = ConnectionState.ERROR
            self.last_error = str(e)
            self.logger.error(f"Connection failed: {e}")
            return Result.error(f"Connection failed: {e}")

    def disconnect(self) -> Result:
        """
        Disconnect from OPC UA server

        Returns:
            Result indicating disconnection success
        """
        try:
            if self.client:
                self.client.disconnect()
                self.client = None

            self.state = ConnectionState.DISCONNECTED
            self.connected_at = None
            self.logger.info(f"Disconnected from {self.target.device.ip}")

            return Result.ok("Disconnected successfully")

        except Exception as e:
            self.logger.warning(f"Disconnect warning: {e}")
            return Result.ok("Disconnected (with warnings)")

    def read(self, node_id: str, data_type: str = None, count: int = 1) -> Result:
        """
        Read value from OPC UA node

        Args:
            node_id: OPC UA Node ID (e.g., "ns=2;s=Temperature")
            data_type: Data type (not used, determined by OPC UA)
            count: Number of elements (not used for single node)

        Returns:
            Result with read data
        """
        try:
            # Ensure connected
            result = self.ensure_connected()
            if not result.success:
                return result

            # Get node
            node = self.client.get_node(node_id)

            # Read value
            value = node.get_value()

            return Result.ok(
                f"Read {node_id}: {value}",
                data=value,
                address=node_id
            )

        except Exception as e:
            self.logger.error(f"Read failed: {e}")
            return Result.error(f"Read failed: {e}")

    def write(self, node_id: str, value: Any, data_type: str = None) -> Result:
        """
        Write value to OPC UA node

        Args:
            node_id: OPC UA Node ID
            value: Value to write
            data_type: Data type (auto-determined)

        Returns:
            Result indicating write success/failure
        """
        try:
            # Ensure connected
            result = self.ensure_connected()
            if not result.success:
                return result

            # Get node
            node = self.client.get_node(node_id)

            # Write value
            node.set_value(value)

            self.logger.info(f"Wrote {node_id} = {value}")
            return Result.ok(f"Wrote {node_id} = {value}")

        except Exception as e:
            self.logger.error(f"Write failed: {e}")
            return Result.error(f"Write failed: {e}")

    def get_device_info(self) -> Result:
        """
        Get OPC UA server information

        Returns:
            Result with device information dict
        """
        try:
            # Ensure connected
            result = self.ensure_connected()
            if not result.success:
                return result

            info = {
                'protocol': 'OPC UA',
                'ip': self.target.device.ip,
                'port': self.port,
                'connected': self.is_connected()
            }

            # Try to get server info
            try:
                # Get server node
                server_node = self.client.get_server_node()

                # Get server status
                server_status = server_node.get_child([
                    "0:ServerStatus"
                ])

                # Get build info
                build_info = server_status.get_child("0:BuildInfo")

                info['product_name'] = build_info.get_child("0:ProductName").get_value()
                info['product_uri'] = build_info.get_child("0:ProductUri").get_value()
                info['manufacturer'] = build_info.get_child("0:ManufacturerName").get_value()
                info['software_version'] = build_info.get_child("0:SoftwareVersion").get_value()

            except Exception as e:
                self.logger.debug(f"Could not get detailed server info: {e}")
                info['server_info_available'] = False

            return Result.ok("Device info retrieved", data=info)

        except Exception as e:
            self.logger.error(f"Failed to get device info: {e}")
            return Result.error(f"Failed to get device info: {e}")

    def browse_nodes(self, node_id: str = "i=85") -> Result:
        """
        Browse OPC UA node tree

        Args:
            node_id: Starting node ID (default: Objects folder)

        Returns:
            Result with list of child nodes
        """
        try:
            result = self.ensure_connected()
            if not result.success:
                return result

            # Get node
            node = self.client.get_node(node_id)

            # Get children
            children = []
            for child in node.get_children():
                try:
                    browse_name = child.get_browse_name().to_string()
                    node_class = child.get_node_class().name

                    child_info = {
                        'node_id': child.nodeid.to_string(),
                        'browse_name': browse_name,
                        'node_class': node_class
                    }

                    # Try to get value if it's a variable
                    if node_class == 'Variable':
                        try:
                            child_info['value'] = child.get_value()
                        except:
                            pass

                    children.append(child_info)
                except:
                    pass

            return Result.ok(
                f"Found {len(children)} child nodes",
                data=children
            )

        except Exception as e:
            return Result.error(f"Browse failed: {e}")
