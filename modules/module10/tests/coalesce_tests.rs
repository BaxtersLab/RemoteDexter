use module10::coalesce::MoveCoalescer;

#[test]
fn test_coalescer_push_and_flush() {
    let mut coalescer = MoveCoalescer::new(3);
    assert_eq!(coalescer.push(1, 2), None);
    assert_eq!(coalescer.push(3, 4), None);
    assert_eq!(coalescer.push(5, 6), Some((9, 12)));
    assert_eq!(coalescer.flush(), None);
}

#[test]
fn test_coalescer_flush_partial() {
    let mut coalescer = MoveCoalescer::new(5);
    assert_eq!(coalescer.push(1, 1), None);
    assert_eq!(coalescer.push(2, 2), None);
    assert_eq!(coalescer.flush(), Some((3, 3)));
    assert_eq!(coalescer.flush(), None);
}