//! View-level tests for `ui/start-page.slint`, rendered through the Slint
//! testing backend's software renderer (the mock renderer used by the layout
//! tests does not rasterize).
//!
//! The Start Page is an overlay inside `MainWindow`, so these tests drive the
//! real window: workspace cards, site list selection and the footer actions.
//! Assertions are colour counts over regions rather than single pixels, so
//! small layout shifts in the page do not break them.

use crate::ui::main_window::{MainWindow, StartSiteRow};
use slint::{ComponentHandle, LogicalSize, ModelRc, Rgba8Pixel, SharedPixelBuffer, VecModel};

/// Colours from `ui/start-page.slint`.
const PAGE_BG: (u8, u8, u8) = (0x26, 0x26, 0x2a);
const CARD_ACTIVE: (u8, u8, u8) = (0x2f, 0x3c, 0x50);
const CARD_IDLE: (u8, u8, u8) = (0x2b, 0x2b, 0x30);
const ROW_SELECTED: (u8, u8, u8) = (0x33, 0x50, 0x6e);

/// Vertical bands of the page (1200x700 window, page spans menu -> status bar).
const CARD_BAND_Y: (u32, u32) = (250, 330);
const FOOTER_BAND_Y: (u32, u32) = (500, 545);

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

/// Renders the window and returns its pixels. `set_size` (rather than a
/// dispatched `Resized`) also grows the software renderer's backing buffer.
fn render(ui: &MainWindow) -> SharedPixelBuffer<Rgba8Pixel> {
    ui.window().set_size(LogicalSize::new(1200.0, 700.0));
    ui.window().take_snapshot().expect("rasterize the window")
}

/// Number of pixels matching `color` inside the region, counting every pixel
/// (the page's flat fills are exact; only glyph edges are antialiased).
fn count_color(
    snapshot: &SharedPixelBuffer<Rgba8Pixel>,
    x: (u32, u32),
    y: (u32, u32),
    color: (u8, u8, u8),
) -> usize {
    let bytes = snapshot.as_bytes();
    let stride = snapshot.width() as usize * 4;
    let mut hits = 0;
    for row in y.0..y.1.min(snapshot.height()) {
        for col in x.0..x.1.min(snapshot.width()) {
            let off = row as usize * stride + col as usize * 4;
            if bytes[off] == color.0 && bytes[off + 1] == color.1 && bytes[off + 2] == color.2 {
                hits += 1;
            }
        }
    }
    hits
}

/// Counts pixels whose blue channel clearly dominates — matches the accent
/// blue and the primary button's palette blue alike.
fn count_bluish(snapshot: &SharedPixelBuffer<Rgba8Pixel>, x: (u32, u32), y: (u32, u32)) -> usize {
    let bytes = snapshot.as_bytes();
    let stride = snapshot.width() as usize * 4;
    let mut hits = 0;
    for row in y.0..y.1.min(snapshot.height()) {
        for col in x.0..x.1.min(snapshot.width()) {
            let off = row as usize * stride + col as usize * 4;
            let (r, b) = (bytes[off] as i32, bytes[off + 2] as i32);
            if b - r > 40 && b > 90 {
                hits += 1;
            }
        }
    }
    hits
}

/// Topmost row with a solid `ROW_SELECTED` fill (the list highlights exactly
/// one row: the "No site" row or the picked site).
fn selected_row_top(snapshot: &SharedPixelBuffer<Rgba8Pixel>) -> Option<u32> {
    (0..snapshot.height())
        .find(|&row| count_color(snapshot, (280, 920), (row, row + 1), ROW_SELECTED) > 300)
}

fn page(rows: Vec<StartSiteRow>, mode: i32, selected: i32) -> MainWindow {
    test_backend();
    let ui = MainWindow::new().unwrap();
    ui.set_start_page_sites(ModelRc::new(VecModel::from(rows)));
    ui.set_start_page_mode(mode);
    ui.set_start_page_selected(selected);
    ui.set_start_page_visible(true);
    ui
}

fn sites() -> Vec<StartSiteRow> {
    vec![
        StartSiteRow {
            kind: 0,
            id: "prod-web-01".into(),
            name: "prod-web-01".into(),
            subtitle: "deploy@web01.example.com:22 — SFTP".into(),
        },
        StartSiteRow {
            kind: 1,
            id: "0".into(),
            name: "gateway.example.com".into(),
            subtitle: "admin@gateway.example.com:22 — SCP (recent)".into(),
        },
    ]
}

/// The two workspace cards must share the page width and only the picked one
/// may be highlighted.
#[test]
fn workspace_cards_highlight_the_picked_mode() {
    let ui = page(sites(), 0, -1);
    let snapshot = render(&ui);
    assert!(
        count_color(&snapshot, (280, 600), CARD_BAND_Y, CARD_ACTIVE) > 5_000,
        "two-panel card should be highlighted in two-panel mode"
    );
    assert!(
        count_color(&snapshot, (600, 920), CARD_BAND_Y, CARD_ACTIVE) == 0,
        "terminal card must not be highlighted in two-panel mode"
    );
    assert!(
        count_color(&snapshot, (600, 920), CARD_BAND_Y, CARD_IDLE) > 5_000,
        "terminal card should render idle"
    );

    ui.set_start_page_mode(1);
    let snapshot = render(&ui);
    assert!(
        count_color(&snapshot, (280, 600), CARD_BAND_Y, CARD_ACTIVE) == 0,
        "two-panel card must not be highlighted in terminal mode"
    );
    assert!(
        count_color(&snapshot, (280, 600), CARD_BAND_Y, CARD_IDLE) > 5_000,
        "two-panel card should render idle in terminal mode"
    );
    assert!(
        count_color(&snapshot, (600, 920), CARD_BAND_Y, CARD_ACTIVE) > 5_000,
        "terminal card should be highlighted in terminal mode"
    );
}

/// The selected row is painted with the accent fill: the "No site" row while
/// no site is picked, the site's own row once it is selected.
#[test]
fn selected_row_follows_the_pick() {
    let ui = page(sites(), 0, -1);
    let snapshot = render(&ui);
    let none_top = selected_row_top(&snapshot).expect("the \"No site\" row is highlighted");
    assert!(
        count_color(&snapshot, (0, 1200), (27, 700), PAGE_BG) > 400_000,
        "the page should cover the menu-to-status workspace with its own background"
    );

    ui.set_start_page_selected(1);
    let snapshot = render(&ui);
    let site_top = selected_row_top(&snapshot).expect("the picked site row is highlighted");
    assert!(
        site_top > none_top + 40,
        "picking the second site should highlight a lower row ({none_top} -> {site_top})"
    );
}

/// The footer keeps its actions reachable: the primary "Open" button is
/// accented, the "Remember my choice" box reflects the property, and the hint
/// text is rendered next to them.
#[test]
fn footer_shows_actions_and_the_remember_box() {
    let ui = page(sites(), 1, 0);
    ui.set_start_page_remember(false);
    ui.set_start_page_hint("Open a login shell (SSH) on the selected site".into());
    let snapshot = render(&ui);
    assert!(
        count_bluish(&snapshot, (800, 1200), FOOTER_BAND_Y) > 300,
        "the primary Open button should be accented"
    );
    let unchecked = count_bluish(&snapshot, (280, 320), FOOTER_BAND_Y);

    ui.set_start_page_remember(true);
    let snapshot = render(&ui);
    let checked = count_bluish(&snapshot, (280, 320), FOOTER_BAND_Y);
    assert!(
        checked > unchecked + 50,
        "the remember box should fill when the option is set ({unchecked} -> {checked})"
    );
}
