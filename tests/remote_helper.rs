use std::io::Cursor;

use codex_ssh_bridge::remote_helper_protocol::{
    Frame, FrameKind, read_frame, write_frame,
};

#[test]
fn helper_wire_round_trips_binary_and_empty_payloads() {
    let frames = [
        Frame {
            kind: FrameKind::Stdout,
            request_id: 7,
            payload: vec![0, b'\n', 0xff],
        },
        Frame {
            kind: FrameKind::Ready,
            request_id: 7,
            payload: Vec::new(),
        },
    ];
    let mut bytes = Vec::new();
    for frame in &frames {
        write_frame(&mut bytes, frame, 64).unwrap();
    }
    let mut input = bytes.as_slice();
    assert_eq!(read_frame(&mut input, 64).unwrap(), Some(frames[0].clone()));
    assert_eq!(read_frame(&mut input, 64).unwrap(), Some(frames[1].clone()));
    assert_eq!(read_frame(&mut input, 64).unwrap(), None);
}

#[test]
fn helper_wire_rejects_oversized_and_truncated_payloads() {
    let oversized = Frame {
        kind: FrameKind::Data,
        request_id: 1,
        payload: vec![1, 2, 3],
    };
    let mut output = Vec::new();
    assert!(write_frame(&mut output, &oversized, 2).is_err());

    let mut truncated = Cursor::new(b"CXSB1 DATA 1 4\nxy".to_vec());
    assert!(read_frame(&mut truncated, 64).is_err());
}

