//! View-level tests for `ui/console.slint`, driven through the Slint testing
//! backend. `ui/console-test.slint` wraps `ConsoleView` in a `Window` (the view
//! itself is a plain `Rectangle`, so it cannot be a window root) and forwards
//! the properties these tests inspect.

use crate::ui::console_test::{ConsoleRow, ConsoleRun, ConsoleTestWindow};
use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{Color, ComponentHandle, LogicalPosition, LogicalSize, ModelRc, VecModel};
use std::cell::RefCell;
use std::rc::Rc;

/// Padding of the console view's outer layout (see ui/console.slint); pointer
/// positions must account for it when addressing grid cells.
const PADDING: f32 = 4.0;

/// Installs the testing backend on the current test thread. Slint 1.17 keeps
/// the platform thread-local, so (unlike a process-wide backend) this is safe
/// to do once per test thread. `take_snapshot` needs a real rasterizer, hence
/// the explicit software renderer instead of the default mock one.
fn test_backend() {
    thread_local! {
        static INIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    if !INIT.with(|c| c.replace(true)) {
        slint::platform::set_platform(Box::new(i_slint_backend_testing::TestingBackend::new(
            i_slint_backend_testing::TestingBackendOptions {
                mock_time: true,
                threading: false,
                renderer_name: Some("software".into()),
            },
        )))
        .expect("platform already initialized");
    }
}

/// Creates a window and forces a layout pass by rendering it.
fn laid_out_window(width: f32, height: f32) -> ConsoleTestWindow {
    let window = ConsoleTestWindow::new().unwrap();
    window.window().dispatch_event(WindowEvent::Resized {
        size: LogicalSize::new(width, height),
    });
    let _ = window.window().take_snapshot().unwrap();
    window
}

fn window(width: f32, height: f32) -> ConsoleTestWindow {
    test_backend();
    laid_out_window(width, height)
}

/// Centre of cell (col, row) in window coordinates; the grid is inset by the
/// view's padding.
fn cell_position(window: &ConsoleTestWindow, col: i32, row: i32) -> LogicalPosition {
    LogicalPosition::new(
        PADDING + (col as f32 + 0.5) * window.get_cell_width(),
        PADDING + (row as f32 + 0.5) * window.get_cell_height(),
    )
}

fn drag(window: &ConsoleTestWindow, from: (i32, i32), to: (i32, i32)) {
    let start = cell_position(window, from.0, from.1);
    let end = cell_position(window, to.0, to.1);
    window
        .window()
        .dispatch_event(WindowEvent::PointerMoved { position: start });
    window.window().dispatch_event(WindowEvent::PointerPressed {
        position: start,
        button: PointerEventButton::Left,
    });
    window
        .window()
        .dispatch_event(WindowEvent::PointerMoved { position: end });
    window
        .window()
        .dispatch_event(WindowEvent::PointerReleased {
            position: end,
            button: PointerEventButton::Left,
        });
}

#[test]
fn grid_size_follows_the_layout() {
    test_backend();
    // Note: the headless software renderer allocates its buffer at first render
    // (800x600 here) and cannot grow it, so this test starts large and shrinks.
    let window = ConsoleTestWindow::new().unwrap();
    window.window().dispatch_event(WindowEvent::Resized {
        size: LogicalSize::new(800.0, 600.0),
    });
    let _ = window.window().take_snapshot().unwrap();
    let (cols, rows) = (window.get_grid_cols(), window.get_grid_rows());
    assert!(cols > 20 && cols < 500, "unexpected cols: {cols}");
    assert!(rows > 5 && rows < 200, "unexpected rows: {rows}");
    let (cell_width, cell_height) = (window.get_cell_width(), window.get_cell_height());
    assert!(cell_width > 4.0 && cell_height > 4.0);

    // The grid spans the window minus the 4px padding on each side; the last
    // column is only as wide as what is left over.
    let check = |spanned: f32, available: f32, cell: f32| {
        assert!(
            spanned <= available + 0.5 && spanned > available - cell - 0.5,
            "grid {spanned} vs available {available}"
        );
    };
    check(cols as f32 * cell_width, 800.0 - 2.0 * PADDING, cell_width);
    check(
        rows as f32 * cell_height,
        600.0 - 2.0 * PADDING,
        cell_height,
    );

    window.window().dispatch_event(WindowEvent::Resized {
        size: LogicalSize::new(400.0, 300.0),
    });
    let _ = window.window().take_snapshot().unwrap();
    let (small_cols, small_rows) = (window.get_grid_cols(), window.get_grid_rows());
    assert!(
        small_cols < cols && small_rows < rows,
        "grid should shrink with the window: {cols}x{rows} -> {small_cols}x{small_rows}"
    );
    assert_eq!(
        window.get_cell_width(),
        cell_width,
        "cell metrics must not depend on the window size"
    );
}

#[test]
fn drag_selection_reports_normalized_cells() {
    let window = window(800.0, 400.0);
    drag(&window, (1, 1), (4, 3));
    assert_eq!(window.get_sel_start_row(), 1);
    assert_eq!(window.get_sel_start_col(), 1);
    assert_eq!(window.get_sel_end_row(), 3);
    assert_eq!(window.get_sel_end_col(), 4);

    // Dragging backwards selects the same rectangle (start <= end).
    drag(&window, (4, 3), (1, 1));
    assert_eq!(window.get_sel_start_row(), 1);
    assert_eq!(window.get_sel_start_col(), 1);
    assert_eq!(window.get_sel_end_row(), 3);
    assert_eq!(window.get_sel_end_col(), 4);

    // A plain click clears the selection.
    let centre = cell_position(&window, 2, 2);
    window
        .window()
        .dispatch_event(WindowEvent::PointerMoved { position: centre });
    window.window().dispatch_event(WindowEvent::PointerPressed {
        position: centre,
        button: PointerEventButton::Left,
    });
    window
        .window()
        .dispatch_event(WindowEvent::PointerReleased {
            position: centre,
            button: PointerEventButton::Left,
        });
    assert_eq!(window.get_sel_start_row(), -1);
}

#[test]
fn typing_reaches_the_console_after_a_click() {
    let window = window(800.0, 400.0);
    let seen: Rc<RefCell<Vec<(String, i32)>>> = Rc::new(RefCell::new(Vec::new()));
    window.on_probe({
        let seen = seen.clone();
        move |text, mods| seen.borrow_mut().push((text.to_string(), mods))
    });

    // Keys go nowhere until the console owns the focus.
    window
        .window()
        .dispatch_event(WindowEvent::KeyPressed { text: "x".into() });
    assert!(seen.borrow().is_empty(), "no focus, no key");

    // Clicking the grid focuses it ...
    let centre = cell_position(&window, 2, 2);
    window
        .window()
        .dispatch_event(WindowEvent::PointerMoved { position: centre });
    window.window().dispatch_event(WindowEvent::PointerPressed {
        position: centre,
        button: PointerEventButton::Left,
    });
    window
        .window()
        .dispatch_event(WindowEvent::PointerReleased {
            position: centre,
            button: PointerEventButton::Left,
        });

    // ... and then keys arrive with their modifiers decoded.
    window.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::UpArrow.into(),
    });
    window
        .window()
        .dispatch_event(WindowEvent::KeyPressed { text: "a".into() });
    let seen = seen.borrow().clone();
    assert_eq!(
        seen,
        vec![
            (String::new(), 11), // SpecialKey::Up
            ("a".to_string(), 0),
        ]
    );
}

#[test]
fn runs_paint_at_their_cell_positions() {
    let window = window(400.0, 200.0);
    let (cell_width, cell_height) = (window.get_cell_width(), window.get_cell_height());
    window.set_rows(ModelRc::new(VecModel::from(vec![ConsoleRow {
        runs: ModelRc::new(VecModel::from(vec![ConsoleRun {
            col: 2,
            cells: 3,
            text: "abc".into(),
            fg: Color::from_rgb_u8(0xff, 0x00, 0x00),
            bg: Color::from_rgb_u8(0x00, 0x00, 0x00),
            bold: false,
            italic: false,
            dim: false,
            inverse: false,
        }])),
    }])));

    let snapshot = window.window().take_snapshot().unwrap();
    let (width, height) = (snapshot.width(), snapshot.height());
    let pixels = snapshot.as_slice();
    let is_red = |x: u32, y: u32| {
        let pixel = &pixels[(y * width + x) as usize];
        pixel.r > 120 && pixel.g < 90 && pixel.b < 90
    };
    let scan = |x0: u32, x1: u32| {
        let y1 = (PADDING + cell_height).ceil() as u32;
        (0..y1.min(height)).any(|y| (x0..x1).any(|x| is_red(x, y)))
    };
    let run_left = (PADDING + 2.0 * cell_width).floor() as u32;
    let run_right = (PADDING + 5.0 * cell_width).ceil().min(width as f32) as u32;
    assert!(
        run_left > 4 && run_right > run_left,
        "cell width looks wrong: {cell_width}px in a {width}x{height} snapshot"
    );
    assert!(
        scan(run_left, run_right),
        "the run should paint inside cols 2..5"
    );
    // ... and nowhere to the left of its column.
    assert!(!scan(0, run_left - 2), "nothing should paint before col 2");
}
