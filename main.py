"""Simple STUN connectivity tester for coturn servers.

Usage example:
	python main.py --host stun.allroundai.com --port 3478

The script sends a STUN Binding Request (RFC 5389) to the specified server
and reports whether it received a valid response, including the public
address information advertised by the server.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple


MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
STUN_BINDING_ERROR = 0x0111
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_USERNAME = 0x0006
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_REALM = 0x0014
ATTR_NONCE = 0x0015


@dataclass
class StunResult:
	success: bool
	mapped_address: Optional[str] = None
	mapped_port: Optional[int] = None
	response_from: Optional[Tuple[str, int]] = None
	latency_ms: Optional[float] = None
	error: Optional[str] = None


def _encode_attribute(attr_type: int, value: bytes) -> bytes:
	padding = (4 - (len(value) % 4)) % 4
	return struct.pack("!HH", attr_type, len(value)) + value + (b"\x00" * padding)


def build_stun_message(
	msg_type: int,
	transaction_id: bytes,
	attributes: Optional[List[Tuple[int, bytes]]] = None,
	integrity_key: Optional[bytes] = None,
) -> bytes:
	attributes = attributes or []
	attr_payload = b"".join(_encode_attribute(attr, value) for attr, value in attributes)

	if integrity_key:
		mi_header = struct.pack("!HH", ATTR_MESSAGE_INTEGRITY, 20)
		empty_hmac = b"\x00" * 20
		attr_payload_with_mi = attr_payload + mi_header + empty_hmac
		header = struct.pack(
			"!HHI12s",
			msg_type,
			len(attr_payload_with_mi),
			MAGIC_COOKIE,
			transaction_id,
		)
		partial_message = header + attr_payload + mi_header + empty_hmac
		hmac_value = hmac.new(integrity_key, partial_message, hashlib.sha1).digest()
		return header + attr_payload + mi_header + hmac_value

	header = struct.pack(
		"!HHI12s",
		msg_type,
		len(attr_payload),
		MAGIC_COOKIE,
		transaction_id,
	)
	return header + attr_payload


def build_binding_request(
	attributes: Optional[List[Tuple[int, bytes]]] = None,
	integrity_key: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
	"""Create a STUN binding request message and its transaction ID."""

	transaction_id = secrets.token_bytes(12)
	message = build_stun_message(
		STUN_BINDING_REQUEST,
		transaction_id,
		attributes=attributes,
		integrity_key=integrity_key,
	)
	return message, transaction_id


def xor_bytes(value: bytes, mask: bytes) -> bytes:
	return bytes(a ^ b for a, b in zip(value, mask))


def parse_address_attribute(
	attr_type: int, value: bytes, transaction_id: bytes
) -> Tuple[str, int]:
	if len(value) < 4:
		raise ValueError("STUN attribute too short")

	family = value[1]
	port = struct.unpack("!H", value[2:4])[0]

	if attr_type == ATTR_XOR_MAPPED_ADDRESS:
		port ^= (MAGIC_COOKIE >> 16) & 0xFFFF

	if family == 0x01:  # IPv4
		addr_bytes = value[4:8]
		if len(addr_bytes) != 4:
			raise ValueError("Invalid IPv4 address length")
		if attr_type == ATTR_XOR_MAPPED_ADDRESS:
			addr_bytes = xor_bytes(addr_bytes, struct.pack("!I", MAGIC_COOKIE))
		ip = socket.inet_ntop(socket.AF_INET, addr_bytes)
	elif family == 0x02:  # IPv6
		addr_bytes = value[4:20]
		if len(addr_bytes) != 16:
			raise ValueError("Invalid IPv6 address length")
		if attr_type == ATTR_XOR_MAPPED_ADDRESS:
			mask = struct.pack("!I", MAGIC_COOKIE) + transaction_id
			addr_bytes = xor_bytes(addr_bytes, mask)
		ip = socket.inet_ntop(socket.AF_INET6, addr_bytes)
	else:
		raise ValueError(f"Unsupported address family: {family}")

	return ip, port


def _iter_attributes(data: bytes, msg_length: int) -> Iterator[Tuple[int, bytes]]:
	end = 20 + msg_length
	offset = 20
	while offset + 4 <= min(len(data), end):
		attr_type, attr_length = struct.unpack("!HH", data[offset : offset + 4])
		offset += 4
		value = data[offset : offset + attr_length]
		offset += attr_length
		if attr_length % 4:
			offset += 4 - (attr_length % 4)
		yield attr_type, value


def parse_stun_response(data: bytes, transaction_id: bytes) -> Tuple[str, int]:
	if len(data) < 20:
		raise ValueError("STUN response too short")

	msg_type, msg_length, magic_cookie = struct.unpack("!HHI", data[:8])
	recv_transaction_id = data[8:20]

	if magic_cookie != MAGIC_COOKIE:
		raise ValueError("Invalid STUN magic cookie")
	if recv_transaction_id != transaction_id:
		raise ValueError("Transaction ID mismatch")
	if msg_type != STUN_BINDING_SUCCESS:
		raise ValueError(f"Unexpected STUN message type: 0x{msg_type:04x}")

	for attr_type, value in _iter_attributes(data, msg_length):
		if attr_type in {ATTR_MAPPED_ADDRESS, ATTR_XOR_MAPPED_ADDRESS}:
			return parse_address_attribute(attr_type, value, transaction_id)

	raise ValueError("No (XOR-)MAPPED-ADDRESS attribute found in STUN response")


def parse_error_response(
	data: bytes, transaction_id: bytes
) -> Tuple[int, Optional[str], Optional[bytes], Optional[bytes]]:
	if len(data) < 20:
		raise ValueError("STUN response too short")

	msg_type, msg_length, magic_cookie = struct.unpack("!HHI", data[:8])
	recv_transaction_id = data[8:20]

	if magic_cookie != MAGIC_COOKIE:
		raise ValueError("Invalid STUN magic cookie")
	if recv_transaction_id != transaction_id:
		raise ValueError("Transaction ID mismatch")
	if msg_type != STUN_BINDING_ERROR:
		raise ValueError("Not a STUN error response")

	error_code: Optional[int] = None
	reason: Optional[str] = None
	realm: Optional[bytes] = None
	nonce: Optional[bytes] = None

	for attr_type, value in _iter_attributes(data, msg_length):
		if attr_type == ATTR_ERROR_CODE and len(value) >= 4:
			class_ = value[2] & 0x07
			number = value[3]
			error_code = class_ * 100 + number
			if len(value) > 4:
				reason = value[4:].decode("utf-8", errors="ignore")
		elif attr_type == ATTR_REALM:
			realm = value
		elif attr_type == ATTR_NONCE:
			nonce = value

	if error_code is None:
		raise ValueError("Error response missing error code")

	return error_code, reason, realm, nonce


def build_integrity_key(username: str, realm: bytes, password: str) -> bytes:
	try:
		realm_text = realm.decode("utf-8")
	except UnicodeDecodeError as exc:
		raise ValueError("Realm attribute is not valid UTF-8") from exc
	material = f"{username}:{realm_text}:{password}".encode("utf-8")
	return hashlib.md5(material).digest()


def perform_authenticated_binding(
	sock: socket.socket,
	server: Tuple[str, int],
	timeout: float,
	username: str,
	password: str,
	realm: bytes,
	nonce: bytes,
) -> Tuple[str, int, Tuple[str, int], float]:
	attributes = [
		(ATTR_USERNAME, username.encode("utf-8")),
		(ATTR_REALM, realm),
		(ATTR_NONCE, nonce),
	]
	integrity_key = build_integrity_key(username, realm, password)
	request, transaction_id = build_binding_request(attributes, integrity_key)

	sock.settimeout(timeout)
	start = time.perf_counter()
	sock.sendto(request, server)
	data, response_from = sock.recvfrom(2048)
	latency = (time.perf_counter() - start) * 1000

	msg_type = struct.unpack("!H", data[:2])[0]
	if msg_type != STUN_BINDING_SUCCESS:
		error_code, reason, *_ = parse_error_response(data, transaction_id)
		raise ValueError(
			f"Authentication attempt failed with error {error_code}"
			+ (f" ({reason})" if reason else "")
		)

	ip, mapped_port = parse_stun_response(data, transaction_id)
	return ip, mapped_port, response_from, latency


def check_stun_server(
	host: str,
	port: int,
	timeout: float,
	attempts: int,
	username: Optional[str] = None,
	password: Optional[str] = None,
) -> StunResult:
	last_error: Optional[str] = None

	for attempt in range(1, attempts + 1):
		try:
			request, transaction_id = build_binding_request()
			with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
				sock.settimeout(timeout)
				start = time.perf_counter()
				sock.sendto(request, (host, port))
				data, response_from = sock.recvfrom(2048)
				latency = (time.perf_counter() - start) * 1000
				msg_type = struct.unpack("!H", data[:2])[0]

				if msg_type == STUN_BINDING_SUCCESS:
					ip, mapped_port = parse_stun_response(data, transaction_id)
					return StunResult(
						success=True,
						mapped_address=ip,
						mapped_port=mapped_port,
						response_from=response_from,
						latency_ms=latency,
					)

				if msg_type == STUN_BINDING_ERROR:
					error_code, reason, realm, nonce = parse_error_response(
						data, transaction_id
					)
					if error_code in {401, 438}:
						if not realm or not nonce:
							last_error = (
								f"Attempt {attempt}: auth challenge missing realm/nonce"
							)
							continue
						if not username or not password:
							last_error = (
								f"Attempt {attempt}: server requested authentication"
								" but script has no credentials configured"
							)
							continue
						try:
							ip, mapped_port, response_from, auth_latency = (
								perform_authenticated_binding(
									sock,
									(host, port),
									timeout,
									username,
									password,
									realm,
									nonce,
								)
							)
							return StunResult(
								success=True,
								mapped_address=ip,
								mapped_port=mapped_port,
								response_from=response_from,
								latency_ms=auth_latency,
							)
						except (socket.timeout, TimeoutError):
							last_error = (
								f"Attempt {attempt}: auth retry timed out after {timeout:.1f}s"
							)
						except ValueError as exc:
							last_error = f"Attempt {attempt}: {exc}"
						continue

					last_error = (
						f"Attempt {attempt}: server returned error {error_code}"
						+ (f" ({reason})" if reason else "")
					)
					continue

				last_error = (
					f"Attempt {attempt}: unexpected STUN message type 0x{msg_type:04x}"
				)
		except (socket.timeout, TimeoutError):
			last_error = f"Attempt {attempt}: request timed out after {timeout:.1f}s"
		except OSError as exc:
			last_error = f"Attempt {attempt}: socket error ({exc})"
		except ValueError as exc:
			last_error = f"Attempt {attempt}: invalid response ({exc})"

	return StunResult(success=False, error=last_error)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Test coturn/STUN server availability")
	parser.add_argument(
		"--host",
		default="stun.l.google.com",
		help="STUN/TURN server hostname or IP (default: %(default)s)",
	)
	parser.add_argument(
		"--port",
		type=int,
		default=19302,
		help="Server port (default: %(default)s)",
	)
	parser.add_argument(
		"--timeout",
		type=float,
		default=2.0,
		help="Socket timeout in seconds (default: %(default)s)",
	)
	parser.add_argument(
		"--attempts",
		type=int,
		default=3,
		help="Number of retries before failing (default: %(default)s)",
	)
	parser.add_argument(
		"--username",
		help="Username for long-term credential authentication (optional)",
	)
	parser.add_argument(
		"--password",
		help="Password for long-term credential authentication (optional)",
	)
	args = parser.parse_args(argv)

	if bool(args.username) ^ bool(args.password):
		parser.error("--username and --password must be provided together")

	return args


def main(argv: Optional[list[str]] = None) -> int:
	args = parse_args(argv)
	result = check_stun_server(
		args.host,
		args.port,
		args.timeout,
		args.attempts,
		args.username,
		args.password,
	)

	if result.success:
		print("✅ STUN server responded successfully!")
		response_str = (
			f"{result.response_from[0]}:{result.response_from[1]}"
			if result.response_from
			else "unknown (no source address)"
		)
		print(f"  Response from: {response_str}")
		print(f"  Latency: {result.latency_ms:.2f} ms")
		print(
			f"  Reported mapped address: {result.mapped_address}:{result.mapped_port}"
		)
		return 0

	print("❌ Failed to reach STUN server.")
	if result.error:
		print(f"  Last error: {result.error}")
	return 1


if __name__ == "__main__":
	sys.exit(main())
