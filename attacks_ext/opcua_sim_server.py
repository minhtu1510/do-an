#!/usr/bin/env python3
"""
attacks_ext/opcua_sim_server.py
OPC-UA Simulation Server — tạo fake tags cho HMI attack scenarios.

Chạy background:
  python -m attacks_ext.opcua_sim_server --port 4840

Tags tạo ra:
  PLC.Tank1.Level     (Float, 50.0)    — HMI_FAKE_DISPLAY  ghi đè
  PLC.Pump1.Status    (Bool,  True)    — HMI_FAKE_DISPLAY  ghi đè  
  PLC.Temp.Sensor1    (Float, 25.0)    — HMI_FAKE_DISPLAY  ghi đè
  PLC.Alarms.HighLevel  (Bool, False)  — HMI_ALARM_SUPPRESS subscribe
  PLC.Alarms.LowPressure(Bool, False)  — HMI_ALARM_SUPPRESS subscribe
  PLC.Alarms.MotorFault (Bool, False)  — HMI_ALARM_SUPPRESS subscribe
  PLC.Alarms.TempHigh   (Bool, False)  — HMI_ALARM_SUPPRESS subscribe
"""

import asyncio
import signal
import sys
import argparse


async def run_server(host: str, port: int):
    try:
        from asyncua import Server, ua
    except ImportError:
        print("[!] asyncua chua cai: pip install asyncua")
        sys.exit(1)

    server = Server()
    server.set_endpoint(f"opc.tcp://{host}:{port}")
    server.set_server_name("ICS HMI Simulation Server")
    await server.init()

    idx = await server.register_namespace("PLC")

    objects = server.nodes.objects
    plc = await objects.add_object(idx, "PLC")

    # ── Process tags (HMI_FAKE_DISPLAY) ───────────────────────────
    tank_level = await plc.add_variable(idx, "Tank1.Level", 50.0)
    pump_status = await plc.add_variable(idx, "Pump1.Status", True)
    temp_sensor = await plc.add_variable(idx, "Temp.Sensor1", 25.0)

    await tank_level.set_writable()
    await pump_status.set_writable()
    await temp_sensor.set_writable()

    # ── Alarm tags (HMI_ALARM_SUPPRESS) ───────────────────────────
    alarms = await plc.add_object(idx, "Alarms")
    alarm_high = await alarms.add_variable(idx, "HighLevel", False)
    alarm_low = await alarms.add_variable(idx, "LowPressure", False)
    alarm_motor = await alarms.add_variable(idx, "MotorFault", False)
    alarm_temp = await alarms.add_variable(idx, "TempHigh", False)

    await alarm_high.set_writable()
    await alarm_low.set_writable()
    await alarm_motor.set_writable()
    await alarm_temp.set_writable()

    print(f"[OPC-UA Server] Running on opc.tcp://{host}:{port}")
    print(f"  Namespace idx: {idx}")
    print(f"  Tags:")
    print(f"    ns={idx};s=PLC.Tank1.Level    = 50.0  (writable)")
    print(f"    ns={idx};s=PLC.Pump1.Status   = True  (writable)")
    print(f"    ns={idx};s=PLC.Temp.Sensor1   = 25.0  (writable)")
    print(f"    ns={idx};s=PLC.Alarms.HighLevel   (writable)")
    print(f"    ns={idx};s=PLC.Alarms.LowPressure (writable)")
    print(f"    ns={idx};s=PLC.Alarms.MotorFault  (writable)")
    print(f"    ns={idx};s=PLC.Alarms.TempHigh    (writable)")
    print(f"  Ctrl+C to stop")

    stop_event = asyncio.Event()

    def _signal_handler():
        stop_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            pass

    await stop_event.wait()
    await server.stop()
    print("[OPC-UA Server] Stopped")


def main():
    p = argparse.ArgumentParser(description="OPC-UA Simulation Server for ICS HMI Attacks")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=4840)
    args = p.parse_args()

    try:
        asyncio.run(run_server(args.host, args.port))
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()
