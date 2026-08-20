"""Protocol-Specific Packet Dissectors"""

from typing import Dict, Any, Optional, List
import struct
from datetime import datetime


class ProtocolDissector:
    """Base class for protocol dissectors"""

    @staticmethod
    def dissect(raw_data: bytes) -> Dict[str, Any]:
        """
        Dissect packet data into structured format

        Returns:
            Dictionary with dissected fields
        """
        raise NotImplementedError


class S7Dissector(ProtocolDissector):
    """Siemens S7 Protocol Dissector"""

    FUNCTION_CODES = {
        0x04: "Read Var",
        0x05: "Write Var",
        0x1A: "Request Download",
        0x1B: "Download Block",
        0x1C: "Download Ended",
        0x1D: "Start Upload",
        0x1E: "Upload",
        0x1F: "End Upload",
        0x28: "PLC Control",
        0x29: "PLC Stop",
        0xF0: "Setup Communication"
    }

    AREA_CODES = {
        0x81: "Input (I)",
        0x82: "Output (Q)",
        0x83: "Marker (M)",
        0x84: "Data Block (DB)",
        0x1C: "Counter (C)",
        0x1D: "Timer (T)"
    }

    @staticmethod
    def dissect(raw_data: bytes) -> Dict[str, Any]:
        """Dissect S7 packet"""
        if len(raw_data) < 10:
            return {"error": "Packet too short"}

        dissected = {
            "protocol": "S7",
            "layers": []
        }

        try:
            # TPKT Layer
            tpkt = {
                "name": "TPKT",
                "fields": {
                    "Version": raw_data[0],
                    "Reserved": raw_data[1],
                    "Length": struct.unpack('>H', raw_data[2:4])[0]
                }
            }
            dissected["layers"].append(tpkt)

            # COTP Layer (ISO 8073)
            if len(raw_data) > 7:
                cotp = {
                    "name": "COTP",
                    "fields": {
                        "Length": raw_data[4],
                        "PDU Type": f"0x{raw_data[5]:02X}",
                        "TPDU Number": raw_data[6] if len(raw_data) > 6 else 0
                    }
                }
                dissected["layers"].append(cotp)

            # S7 Header
            if len(raw_data) > 10:
                s7_header = {
                    "name": "S7 Header",
                    "fields": {
                        "Protocol ID": f"0x{raw_data[7]:02X}",
                        "Message Type": S7Dissector._get_message_type(raw_data[8]),
                        "Reserved": f"0x{raw_data[9]:04X}",
                        "PDU Reference": struct.unpack('>H', raw_data[10:12])[0] if len(raw_data) > 11 else 0,
                        "Parameter Length": struct.unpack('>H', raw_data[12:14])[0] if len(raw_data) > 13 else 0,
                        "Data Length": struct.unpack('>H', raw_data[14:16])[0] if len(raw_data) > 15 else 0
                    }
                }
                dissected["layers"].append(s7_header)

            # S7 Parameter
            if len(raw_data) > 17:
                function_code = raw_data[17]
                s7_param = {
                    "name": "S7 Parameter",
                    "fields": {
                        "Function": S7Dissector.FUNCTION_CODES.get(function_code, f"Unknown (0x{function_code:02X})")
                    }
                }

                # Parse based on function code
                if function_code == 0x04:  # Read Var
                    s7_param["fields"]["Item Count"] = raw_data[18] if len(raw_data) > 18 else 0

                    # Parse read items
                    if len(raw_data) > 19:
                        items = []
                        offset = 19
                        for i in range(s7_param["fields"]["Item Count"]):
                            if offset + 12 <= len(raw_data):
                                item = {
                                    "Variable Spec": f"0x{raw_data[offset]:02X}",
                                    "Length": raw_data[offset + 1],
                                    "Syntax ID": f"0x{raw_data[offset + 2]:02X}",
                                    "Transport Size": raw_data[offset + 3],
                                    "Length": struct.unpack('>H', raw_data[offset+4:offset+6])[0],
                                    "DB Number": struct.unpack('>H', raw_data[offset+6:offset+8])[0],
                                    "Area": S7Dissector.AREA_CODES.get(raw_data[offset + 8], f"0x{raw_data[offset+8]:02X}"),
                                    "Address": struct.unpack('>I', b'\x00' + raw_data[offset+9:offset+12])[0] // 8
                                }
                                items.append(item)
                                offset += 12
                        s7_param["fields"]["Items"] = items

                elif function_code == 0x05:  # Write Var
                    s7_param["fields"]["Item Count"] = raw_data[18] if len(raw_data) > 18 else 0

                dissected["layers"].append(s7_param)

            # S7 Data
            if len(raw_data) > 20:
                param_len = struct.unpack('>H', raw_data[12:14])[0] if len(raw_data) > 13 else 0
                data_offset = 17 + param_len

                if data_offset < len(raw_data):
                    data_len = min(len(raw_data) - data_offset, 32)  # Show first 32 bytes
                    s7_data = {
                        "name": "S7 Data",
                        "fields": {
                            "Data (hex)": raw_data[data_offset:data_offset+data_len].hex(),
                            "Length": len(raw_data) - data_offset
                        }
                    }
                    dissected["layers"].append(s7_data)

        except Exception as e:
            dissected["error"] = f"Dissection error: {str(e)}"

        return dissected

    @staticmethod
    def _get_message_type(type_code: int) -> str:
        """Get message type name"""
        types = {
            0x01: "Job Request",
            0x02: "Ack",
            0x03: "Ack Data",
            0x07: "Userdata"
        }
        return types.get(type_code, f"Unknown (0x{type_code:02X})")


class ModbusDissector(ProtocolDissector):
    """Modbus TCP Protocol Dissector"""

    FUNCTION_CODES = {
        1: "Read Coils",
        2: "Read Discrete Inputs",
        3: "Read Holding Registers",
        4: "Read Input Registers",
        5: "Write Single Coil",
        6: "Write Single Register",
        15: "Write Multiple Coils",
        16: "Write Multiple Registers",
        23: "Read/Write Multiple Registers"
    }

    @staticmethod
    def dissect(raw_data: bytes) -> Dict[str, Any]:
        """Dissect Modbus TCP packet"""
        if len(raw_data) < 8:
            return {"error": "Packet too short"}

        dissected = {
            "protocol": "Modbus TCP",
            "layers": []
        }

        try:
            # MBAP Header
            mbap = {
                "name": "MBAP Header",
                "fields": {
                    "Transaction ID": struct.unpack('>H', raw_data[0:2])[0],
                    "Protocol ID": struct.unpack('>H', raw_data[2:4])[0],
                    "Length": struct.unpack('>H', raw_data[4:6])[0],
                    "Unit ID": raw_data[6]
                }
            }
            dissected["layers"].append(mbap)

            # Modbus PDU
            function_code = raw_data[7]
            pdu = {
                "name": "Modbus PDU",
                "fields": {
                    "Function Code": f"{function_code} - {ModbusDissector.FUNCTION_CODES.get(function_code, 'Unknown')}"
                }
            }

            # Parse based on function code
            if function_code in [1, 2, 3, 4]:  # Read functions
                if len(raw_data) >= 12:
                    pdu["fields"]["Starting Address"] = struct.unpack('>H', raw_data[8:10])[0]
                    pdu["fields"]["Quantity"] = struct.unpack('>H', raw_data[10:12])[0]

            elif function_code in [5, 6]:  # Write single
                if len(raw_data) >= 12:
                    pdu["fields"]["Address"] = struct.unpack('>H', raw_data[8:10])[0]
                    pdu["fields"]["Value"] = struct.unpack('>H', raw_data[10:12])[0]

            elif function_code in [15, 16]:  # Write multiple
                if len(raw_data) >= 13:
                    pdu["fields"]["Starting Address"] = struct.unpack('>H', raw_data[8:10])[0]
                    pdu["fields"]["Quantity"] = struct.unpack('>H', raw_data[10:12])[0]
                    pdu["fields"]["Byte Count"] = raw_data[12]

                    # Show data
                    if len(raw_data) > 13:
                        data_len = min(raw_data[12], len(raw_data) - 13)
                        pdu["fields"]["Data (hex)"] = raw_data[13:13+data_len].hex()

            # Check for exception
            if function_code >= 0x80:
                pdu["fields"]["Exception Code"] = raw_data[8] if len(raw_data) > 8 else 0
                pdu["name"] += " (Exception Response)"

            dissected["layers"].append(pdu)

        except Exception as e:
            dissected["error"] = f"Dissection error: {str(e)}"

        return dissected


class OPCUADissector(ProtocolDissector):
    """OPC UA Protocol Dissector"""

    MESSAGE_TYPES = {
        b'HEL': 'Hello',
        b'ACK': 'Acknowledge',
        b'ERR': 'Error',
        b'RHE': 'Reverse Hello',
        b'MSG': 'Message',
        b'OPN': 'Open Secure Channel',
        b'CLO': 'Close Secure Channel'
    }

    @staticmethod
    def dissect(raw_data: bytes) -> Dict[str, Any]:
        """Dissect OPC UA packet"""
        if len(raw_data) < 8:
            return {"error": "Packet too short"}

        dissected = {
            "protocol": "OPC UA",
            "layers": []
        }

        try:
            # OPC UA Header
            msg_type = raw_data[0:3]
            chunk_type = chr(raw_data[3]) if len(raw_data) > 3 else '?'
            msg_size = struct.unpack('<I', raw_data[4:8])[0] if len(raw_data) >= 8 else 0

            header = {
                "name": "OPC UA Header",
                "fields": {
                    "Message Type": OPCUADissector.MESSAGE_TYPES.get(msg_type, msg_type.decode('ascii', errors='ignore')),
                    "Chunk Type": chunk_type,
                    "Message Size": msg_size
                }
            }
            dissected["layers"].append(header)

            # Parse based on message type
            if msg_type == b'HEL' and len(raw_data) >= 28:
                hello = {
                    "name": "Hello Message",
                    "fields": {
                        "Protocol Version": struct.unpack('<I', raw_data[8:12])[0],
                        "Receive Buffer Size": struct.unpack('<I', raw_data[12:16])[0],
                        "Send Buffer Size": struct.unpack('<I', raw_data[16:20])[0],
                        "Max Message Size": struct.unpack('<I', raw_data[20:24])[0],
                        "Max Chunk Count": struct.unpack('<I', raw_data[24:28])[0]
                    }
                }
                dissected["layers"].append(hello)

            elif msg_type == b'OPN' and len(raw_data) >= 16:
                opn = {
                    "name": "Open Secure Channel",
                    "fields": {
                        "Secure Channel ID": struct.unpack('<I', raw_data[8:12])[0],
                        "Security Policy URI Length": struct.unpack('<I', raw_data[12:16])[0]
                    }
                }
                dissected["layers"].append(opn)

        except Exception as e:
            dissected["error"] = f"Dissection error: {str(e)}"

        return dissected


class DissectorRegistry:
    """Registry for protocol dissectors"""

    _dissectors = {
        'S7': S7Dissector,
        'Modbus TCP': ModbusDissector,
        'OPC UA': OPCUADissector
    }

    @classmethod
    def get_dissector(cls, protocol: str) -> Optional[ProtocolDissector]:
        """Get dissector for protocol"""
        return cls._dissectors.get(protocol)

    @classmethod
    def dissect_packet(cls, protocol: str, raw_data: bytes) -> Dict[str, Any]:
        """Dissect packet using appropriate dissector"""
        dissector = cls.get_dissector(protocol)

        if dissector:
            return dissector.dissect(raw_data)
        else:
            return {
                "protocol": protocol,
                "error": "No dissector available",
                "raw_hex": raw_data[:64].hex()
            }
