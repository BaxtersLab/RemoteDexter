pub struct MoveCoalescer {
    pending_dx: i32,
    pending_dy: i32,
    count: u8,
    max: u8,
}

impl MoveCoalescer {
    pub fn new(max: u8) -> Self {
        MoveCoalescer {
            pending_dx: 0,
            pending_dy: 0,
            count: 0,
            max,
        }
    }

    pub fn push(&mut self, dx: i32, dy: i32) -> Option<(i32, i32)> {
        self.pending_dx += dx;
        self.pending_dy += dy;
        self.count += 1;

        if self.count >= self.max {
            self.flush()
        } else {
            None
        }
    }

    pub fn flush(&mut self) -> Option<(i32, i32)> {
        if self.count > 0 {
            let result = (self.pending_dx, self.pending_dy);
            self.pending_dx = 0;
            self.pending_dy = 0;
            self.count = 0;
            Some(result)
        } else {
            None
        }
    }
}