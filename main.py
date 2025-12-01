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
from enum import Enum
from typing import Iterator, List, Optional, Tuple


class NatType(Enum):
	"""NAT type classifications based on RFC 3489."""
	OPEN = "Open Internet"
	FULL_CONE = "Full Cone NAT"
	RESTRICTED_CONE = "Restricted Cone NAT"
	PORT_RESTRICTED_CONE = "Port Restricted Cone NAT"
	SYMMETRIC = "Symmetric NAT"
	BLOCKED = "UDP Blocked"
	UNKNOWN = "Unknown"


@dataclass
class NatResult:
	"""Result of NAT type detection."""
	nat_type: NatType
	external_ip: Optional[str] = None
	external_port: Optional[int] = None
	details: Optional[str] = None


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


# Default STUN servers for NAT detection
DEFAULT_STUN_SERVERS = [
	("stun.l.google.com", 19302),
	("stun1.l.google.com", 19302),
	("stun2.l.google.com", 19302),
	("stun.cloudflare.com", 3478),
]


def _get_stun_mapping(
	host: str,
	port: int,
	timeout: float,
	local_sock: Optional[socket.socket] = None,
) -> Optional[Tuple[str, int]]:
	"""Get the external IP and port mapping from a STUN server.
	
	If local_sock is provided, it will be reused. Otherwise a new socket is created.
	Returns (external_ip, external_port) or None if failed.
	"""
	try:
		request, transaction_id = build_binding_request()
		
		if local_sock:
			sock = local_sock
			should_close = False
		else:
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			should_close = True
		
		try:
			sock.settimeout(timeout)
			sock.sendto(request, (host, port))
			data, _ = sock.recvfrom(2048)
			
			msg_type = struct.unpack("!H", data[:2])[0]
			if msg_type == STUN_BINDING_SUCCESS:
				ip, mapped_port = parse_stun_response(data, transaction_id)
				return (ip, mapped_port)
		finally:
			if should_close:
				sock.close()
	except (socket.timeout, TimeoutError, OSError, ValueError):
		pass
	
	return None


def detect_nat_type(
	stun_servers: Optional[List[Tuple[str, int]]] = None,
	timeout: float = 2.0,
) -> NatResult:
	"""Detect the NAT type of the current network.
	
	This function uses multiple STUN servers to determine the NAT type.
	The detection algorithm:
	1. Query first STUN server to get external IP/port (Test I)
	2. Query second STUN server with the same local socket (Test II)
	3. Compare the results to determine NAT type
	
	NAT Types:
	- Open Internet: Local IP equals external IP
	- Full Cone: Same external IP:port for all STUN servers
	- Symmetric: Different external port for different destinations
	- Restricted/Port Restricted: Same port mapping, but with filtering
	
	Args:
		stun_servers: List of (host, port) tuples for STUN servers
		timeout: Socket timeout in seconds
	
	Returns:
		NatResult with the detected NAT type and external address
	"""
	servers = stun_servers or DEFAULT_STUN_SERVERS
	
	if len(servers) < 2:
		return NatResult(
			nat_type=NatType.UNKNOWN,
			details="At least 2 STUN servers required for NAT detection"
		)
	
	# Test I: Query first STUN server
	result1 = _get_stun_mapping(servers[0][0], servers[0][1], timeout)
	
	if not result1:
		return NatResult(
			nat_type=NatType.BLOCKED,
			details="Unable to reach STUN server - UDP may be blocked"
		)
	
	external_ip1, external_port1 = result1
	
	# Check if we're on open internet (local IP == external IP)
	try:
		# Get local IP by creating a dummy connection
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
			s.connect((servers[0][0], servers[0][1]))
			local_ip = s.getsockname()[0]
		
		if local_ip == external_ip1:
			return NatResult(
				nat_type=NatType.OPEN,
				external_ip=external_ip1,
				external_port=external_port1,
				details="Public IP address detected - no NAT"
			)
	except OSError:
		pass
	
	# Test II: Query second STUN server with the SAME local socket
	# This tests if the external port changes based on destination
	try:
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
			sock.settimeout(timeout)
			
			# Get mapping from server 1
			mapping1 = _get_stun_mapping(
				servers[0][0], servers[0][1], timeout, sock
			)
			
			if not mapping1:
				return NatResult(
					nat_type=NatType.UNKNOWN,
					external_ip=external_ip1,
					external_port=external_port1,
					details="Failed to get consistent mapping from first server"
				)
			
			# Get mapping from server 2 with same socket
			mapping2 = _get_stun_mapping(
				servers[1][0], servers[1][1], timeout, sock
			)
			
			if not mapping2:
				# Second server unreachable, try third server if available
				if len(servers) > 2:
					mapping2 = _get_stun_mapping(
						servers[2][0], servers[2][1], timeout, sock
					)
			
			if not mapping2:
				return NatResult(
					nat_type=NatType.UNKNOWN,
					external_ip=mapping1[0],
					external_port=mapping1[1],
					details="Unable to reach secondary STUN servers"
				)
			
			# Compare mappings
			ip1, port1 = mapping1
			ip2, port2 = mapping2
			
			if ip1 != ip2:
				# Different external IPs - likely multi-homed or carrier-grade NAT
				return NatResult(
					nat_type=NatType.SYMMETRIC,
					external_ip=ip1,
					external_port=port1,
					details=f"Different external IPs detected ({ip1} vs {ip2})"
				)
			
			if port1 != port2:
				# Same IP but different ports = Symmetric NAT
				return NatResult(
					nat_type=NatType.SYMMETRIC,
					external_ip=ip1,
					external_port=port1,
					details=f"Port mapping changes per destination ({port1} vs {port2})"
				)
			
			# Same IP and same port - could be Full Cone, Restricted Cone, or Port Restricted Cone
			# Without being able to test incoming connections from different IPs,
			# we can only confirm it's a cone NAT (not symmetric)
			# We'll report as Full Cone as the most optimistic classification
			# that matches the observed behavior
			return NatResult(
				nat_type=NatType.FULL_CONE,
				external_ip=ip1,
				external_port=port1,
				details="Consistent port mapping across different destinations"
			)
			
	except OSError as e:
		return NatResult(
			nat_type=NatType.UNKNOWN,
			external_ip=external_ip1,
			external_port=external_port1,
			details=f"Socket error during NAT detection: {e}"
		)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Test coturn/STUN server availability and detect NAT type")
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
	parser.add_argument(
		"--nat-detect",
		action="store_true",
		help="Detect NAT type instead of testing a single STUN server",
	)
	args = parser.parse_args(argv)

	if bool(args.username) ^ bool(args.password):
		parser.error("--username and --password must be provided together")

	return args


def main(argv: Optional[list[str]] = None) -> int:
	args = parse_args(argv)
	
	# NAT detection mode
	if args.nat_detect:
		print("🔍 Detecting NAT type...")
		nat_result = detect_nat_type(timeout=args.timeout)
		
		# Display NAT type icon based on result
		nat_icons = {
			NatType.OPEN: "🌐",
			NatType.FULL_CONE: "🟢",
			NatType.RESTRICTED_CONE: "🟡",
			NatType.PORT_RESTRICTED_CONE: "🟠",
			NatType.SYMMETRIC: "🔴",
			NatType.BLOCKED: "⛔",
			NatType.UNKNOWN: "❓",
		}
		icon = nat_icons.get(nat_result.nat_type, "❓")
		
		print(f"{icon} NAT Type: {nat_result.nat_type.value}")
		if nat_result.external_ip:
			print(f"  External Address: {nat_result.external_ip}:{nat_result.external_port}")
		if nat_result.details:
			print(f"  Details: {nat_result.details}")
		
		# Return 0 for successful detection (even if NAT is restrictive)
		return 0 if nat_result.nat_type != NatType.BLOCKED else 1
	
	# Standard STUN test mode
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
