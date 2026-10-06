import struct
import io
import pytest
from unittest.mock import Mock
from edge import receive_exactly, receive_message

def test_receive_exactly():
    
    mock_sock = Mock()
    mock_sock.recv.side_effect = [b"123", b"45678"]
    
    result = receive_exactly(mock_sock, 8)
    assert result == b"12345678"

def test_receive_message_zero_length_ends_stream():
    mock_sock = Mock()
    # The length of meatadata in header = 0
    mock_sock.recv.return_value = struct.pack("!I", 0)
    
    result = receive_message(mock_sock)
    assert result is None

def test_receive_message_too_large():
    mock_sock = Mock()
   
    mock_sock.recv.return_value = struct.pack("!I", 2 * 1024 * 1024)
    
    with pytest.raises(ValueError, match="Message is too large"):
        receive_message(mock_sock)
