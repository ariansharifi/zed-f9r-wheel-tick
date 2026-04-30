import argparse
import concurrent.futures
import csv
import ipaddress
import json
import threading
from datetime import datetime
from pathlib import Path
import socket
import sys
import time
from dataclasses import dataclass
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from pyubx2 import GET, UBXMessage, UBXReader

try:
    import termios
    import tty
except ImportError:
    termios = None
    tty = None


WHEEL_TICK_VP = 65
WHEEL_DIR_VP = 66
WHEEL_TICK_DATA_TYPE = 10
WHEEL_TICK_COUNT_MASK = (1 << 23) - 1
POLL_INTERVAL_SECONDS = 2.0
READ_TIMEOUT_SECONDS = 2.0
HOST_IP_ADDRESS="127.0.0.1"
API_REQUEST_TIMEOUT_SECONDS = 5.0
RESULTS_CSV = Path(__file__).with_name("wheel_tick_results.csv")

@dataclass
class WheelTickSample:
    time_tag: int
    tick_count: int


def _probe_ubx_api(ip: str, port: int, timeout: float) -> bool:
    url = f"http://{ip}:{port}/gnss_handler/api?ubxClass=MON&ubxID=MON-HW3"
    try:
        with urlopen(Request(url, method="GET"), timeout=timeout) as resp:
            status = getattr(resp, "status", resp.getcode())
            return 200 <= status < 300
    except Exception:
        return False


def _get_local_ip() -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def discover_ubx_device(api_port: int = 7778) -> Optional[str]:
    if _probe_ubx_api("127.0.0.1", api_port, timeout=1.0):
        return "127.0.0.1"

    local_ip = _get_local_ip()
    if not local_ip or local_ip == "127.0.0.1":
        return None

    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    hosts = [str(h) for h in network.hosts() if str(h) != local_ip]
    print(f"Scanning {network} for u-blox device...", flush=True)

    found: list[str] = []
    lock = threading.Lock()
    stop_event = threading.Event()

    def check(ip: str) -> None:
        if stop_event.is_set():
            return
        if _probe_ubx_api(ip, api_port, timeout=2):
            with lock:
                found.append(ip)
            stop_event.set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
        futures = {executor.submit(check, ip) for ip in hosts}
        for _ in concurrent.futures.as_completed(futures):
            if stop_event.is_set():
                for f in futures:
                    f.cancel()
                break

    return found[0] if found else None


def parse_args(host_ip: str = HOST_IP_ADDRESS) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Poll UBX ESF-MEAS and MON-HW3 over TCP and report wheel-tick frequency."
    )
    parser.add_argument("--ubx-host", default=host_ip)
    parser.add_argument("--ubx-port", type=int, default=7779)
    parser.add_argument("--api-host", default=host_ip)
    parser.add_argument("--api-port", type=int, default=7778)
    parser.add_argument("--interval", type=float, default=POLL_INTERVAL_SECONDS)
    parser.add_argument("--timeout", type=float, default=READ_TIMEOUT_SECONDS)
    return parser.parse_args()


def post_config(api_host: str, api_port: int, cfg_key: str, value: int, layer: str = "RAM") -> None:
    query = urlencode(
        {
            "cfgKey": cfg_key,
            "layer": layer,
            "value": value,
        }
    )
    url = f"http://{api_host}:{api_port}/gnss_handler/api/config?{query}"
    request = Request(url, method="POST")
    with urlopen(request, timeout=5) as response:
        status = getattr(response, "status", response.getcode())
        if status < 200 or status >= 300:
            raise RuntimeError(f"Config request failed for {cfg_key}: HTTP {status}")


def apply_startup_config(api_host: str, api_port: int) -> None:
    post_config(api_host, api_port, "CFG_SFODO_USE_WT_PIN", 1)
    post_config(api_host, api_port, "CFG-SFIMU-IMU_EN", 0)


def get_ublox_rest_api(api_host: str, api_port: int, ubx_class: str, ubx_id: str) -> object:
    query = urlencode(
        {
            "ubxClass": ubx_class,
            "ubxID": ubx_id,
        }
    )
    url = f"http://{api_host}:{api_port}/gnss_handler/api?{query}"
    request = Request(url, method="GET")

    try:
        with urlopen(request, timeout=API_REQUEST_TIMEOUT_SECONDS) as response:
            status = getattr(response, "status", response.getcode())
            if status < 200 or status >= 300:
                print(f"u-blox info request failed for {ubx_id}: HTTP {status}", file=sys.stderr)
                return {}
            payload = json.load(response)
    except HTTPError as exc:
        print(f"u-blox info request failed for {ubx_id}: HTTP {exc.code}", file=sys.stderr)
        return {}
    except (URLError, TimeoutError, OSError) as exc:
        print(f"u-blox info request failed for {ubx_id}: {exc}", file=sys.stderr)
        return {}
    except json.JSONDecodeError as exc:
        print(f"u-blox info response was not valid for {ubx_id}: {exc}", file=sys.stderr)
        return {}

    if not isinstance(payload, dict):
        print(f"u-blox info response was not an object for {ubx_id}", file=sys.stderr)
        return {}

    return payload.get("data", {})


def extract_mon_ver_msg(mon_ver: object, prefix: str) -> Optional[str]:
    if isinstance(mon_ver, str):
        return mon_ver.removeprefix(prefix).strip(" \t\r\n\x00") if mon_ver.startswith(prefix) else None

    if isinstance(mon_ver, dict):
        for value in mon_ver.values():
            extracted = extract_mon_ver_msg(value, prefix)
            if extracted:
                return extracted
        return None

    if isinstance(mon_ver, list):
        for value in mon_ver:
            extracted = extract_mon_ver_msg(value, prefix)
            if extracted:
                return extracted
        return None

    return None


def get_ublox_info(api_host: str, api_port: int) -> dict[str, str]:
    result = {"manufacturer": "u-blox"}
    retries = 5

    while retries > 0:
        uid_data = get_ublox_rest_api(api_host, api_port, "SEC", "SEC-UNIQID")
        sec_uid = uid_data.get("uniqueId") if isinstance(uid_data, dict) else None
        if sec_uid:
            result["unique_id"] = str(sec_uid)
            break

        retries -= 1
        if retries > 0:
            time.sleep(5)

    mon_ver = get_ublox_rest_api(api_host, api_port, "MON", "MON-VER")
    if mon_ver:
        model = extract_mon_ver_msg(mon_ver, "MOD=")
        if model:
            result["model"] = model

        firmware = extract_mon_ver_msg(mon_ver, "FWVER=")
        if firmware:
            result["firmware"] = firmware

    return result


def format_ublox_info(info: dict[str, str]) -> str:
    return (
        "u-blox: manufacturer={manufacturer}, model={model}, firmware={firmware}, unique_id={unique_id}".format(
            manufacturer=info.get("manufacturer", "N/A"),
            model=info.get("model", "N/A"),
            firmware=info.get("firmware", "N/A"),
            unique_id=info.get("unique_id", "N/A"),
        )
    )


def poll_message(sock: socket.socket, msg: UBXMessage) -> None:
    sock.sendall(msg.serialize())


def extract_wheel_tick_sample(message) -> Optional[WheelTickSample]:
    if getattr(message, "identity", "") != "ESF-MEAS":
        return None

    num_meas = getattr(message, "numMeas", 0)
    for index in range(1, num_meas + 1):
        suffix = f"_{index:02d}"
        data_type = getattr(message, f"dataType{suffix}", None)
        if data_type != WHEEL_TICK_DATA_TYPE:
            continue

        raw_data_field = getattr(message, f"dataField{suffix}", None)
        time_tag = getattr(message, "timeTag", None)
        if raw_data_field is None or time_tag is None:
            return None

        tick_count = int(raw_data_field) & WHEEL_TICK_COUNT_MASK
        return WheelTickSample(time_tag=int(time_tag), tick_count=tick_count)

    return None


def extract_virtual_pin_state(message, vp_target: int) -> Optional[bool]:
    if getattr(message, "identity", "") != "MON-HW3":
        return None

    n_pins = getattr(message, "nPins", 0)
    for index in range(1, n_pins + 1):
        suffix = f"_{index:02d}"
        vp = getattr(message, f"VP{suffix}", None)
        if vp != vp_target:
            continue

        pin_value = getattr(message, f"pinValue{suffix}", None)
        if pin_value is None:
            return None
        return bool(pin_value)

    return None


def calculate_frequency_khz(previous: Optional[WheelTickSample], current: WheelTickSample) -> Optional[float]:
    if previous is None:
        return None

    delta_time = current.time_tag - previous.time_tag
    if delta_time <= 0:
        return None
    delta_tick = current.tick_count - previous.tick_count
    return delta_tick / delta_time


def drain_polled_messages(
    ubr: UBXReader,
    deadline: float,
) -> tuple[Optional[WheelTickSample], Optional[bool], Optional[bool]]:
    wheel_tick_sample = None
    wheel_tick_pin = None
    wheel_dir_pin = None

    while time.monotonic() < deadline:
        try:
            _, parsed = ubr.read()
        except TimeoutError:
            continue

        if parsed is None:
            continue

        if wheel_tick_sample is None:
            wheel_tick_sample = extract_wheel_tick_sample(parsed)

        if wheel_tick_pin is None:
            wheel_tick_pin = extract_virtual_pin_state(parsed, WHEEL_TICK_VP)

        if wheel_dir_pin is None:
            wheel_dir_pin = extract_virtual_pin_state(parsed, WHEEL_DIR_VP)

        if wheel_tick_sample is not None and wheel_tick_pin is not None and wheel_dir_pin is not None:
            break

    return wheel_tick_sample, wheel_tick_pin, wheel_dir_pin


def format_pin_state(value: Optional[bool]) -> str:
    if value is None:
        return "N/A"
    return "HIGH" if value else "LOW"


def format_frequency_khz(value: Optional[float]) -> str:
    if value is None:
        return "N/A"
    return f"{value:.6f}"


def prompt_test_status() -> Optional[str]:
    while True:
        try:
            answer = input("Was everything ok? [yes/no/cancel]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return None

        if answer in {"yes", "y"}:
            return "pass"
        if answer in {"no", "n"}:
            return "failed"
        if answer in {"cancel", "cancle", "c"}:
            return None
        print("Please type yes, no, or cancel.")


def append_test_result(ublox_info: dict[str, str], test_status: str) -> None:
    write_header = not RESULTS_CSV.exists() or RESULTS_CSV.stat().st_size == 0
    with RESULTS_CSV.open("a", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=["date", "uniq_id", "firmware", "test_status"],
        )
        if write_header:
            writer.writeheader()
        writer.writerow(
            {
                "date": datetime.now().isoformat(timespec="seconds"),
                "uniq_id": ublox_info.get("unique_id", "N/A"),
                "firmware": ublox_info.get("firmware", "N/A"),
                "test_status": test_status,
            }
        )


def record_test_result(ublox_info: dict[str, str]) -> None:
    test_status = prompt_test_status()
    if test_status is None:
        print("Test result not recorded.")
        return

    append_test_result(ublox_info, test_status)
    print(f"Recorded {test_status} in {RESULTS_CSV}")


def prompt_host_ip() -> str:
    try:
        answer = input(f"Enter host IP address [default: {HOST_IP_ADDRESS}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return HOST_IP_ADDRESS
    return answer if answer else HOST_IP_ADDRESS


def main() -> int:
    print("Looking for u-blox device on network...", flush=True)
    host_ip = discover_ubx_device()
    if host_ip:
        print(f"Found u-blox device at {host_ip}", flush=True)
    else:
        print("Device not found automatically.", flush=True)
        host_ip = prompt_host_ip()
    args = parse_args(host_ip)

    ublox_info = get_ublox_info(args.api_host, args.api_port)
    ublox_info_line = format_ublox_info(ublox_info)
    print(ublox_info_line, flush=True)

    try:
        apply_startup_config(args.api_host, args.api_port)
    except (HTTPError, URLError, TimeoutError, OSError, RuntimeError) as exc:
        print(f"Failed to apply GNSS config: {exc}", file=sys.stderr)
        return 1

    esf_meas_poll = UBXMessage("ESF", "ESF-MEAS", GET)
    mon_hw3_poll = UBXMessage("MON", "MON-HW3", GET)

    try:
        with socket.create_connection((args.ubx_host, args.ubx_port), timeout=5) as sock:
            sock.settimeout(args.timeout)
            with sock.makefile("rb") as stream:
                ubr = UBXReader(stream, protfilter=2, quitonerror=0)
                previous_sample = None

                while True:
                    cycle_started = time.monotonic()
                    poll_message(sock, esf_meas_poll)
                    poll_message(sock, mon_hw3_poll)

                    sample, wheel_tick_pin, wheel_dir_pin = drain_polled_messages(
                        ubr,
                        deadline=cycle_started + args.timeout,
                    )
                    frequency_khz = calculate_frequency_khz(previous_sample, sample) if sample else None

                    if sample is not None:
                        previous_sample = sample

                    # set the cursor to it's begining
                    print("\033[H\033[J", end="")
                    print(ublox_info_line)
                    print(
                        "timeTag={time_tag}, WT_PIN={wt_pin}, WD_PIN={wd_pin}, freq={freq} KHz".format(
                            time_tag=sample.time_tag if sample else "N/A",
                            freq=format_frequency_khz(frequency_khz),
                            wt_pin=format_pin_state(wheel_tick_pin),
                            wd_pin=format_pin_state(wheel_dir_pin),
                        ),
                        flush=True,
                    )

                    sleep_for = args.interval - (time.monotonic() - cycle_started)
                    if sleep_for > 0:
                        time.sleep(sleep_for)
    except KeyboardInterrupt:
        print()
        record_test_result(ublox_info)
        return 0
    except (ConnectionError, OSError) as exc:
        print(f"TCP connection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
