// palette

use ratatui::style::{Color, Modifier, Style};

// backgrounds
pub const BG_DARK: Color = Color::Rgb(18, 10, 30);
pub const BG_PANEL: Color = Color::Rgb(28, 18, 48);
pub const BG_HIGHLIGHT: Color = Color::Rgb(45, 28, 72);

// borders
pub const BORDER_DIM: Color = Color::Rgb(60, 40, 90);
pub const BORDER_ACTIVE: Color = Color::Rgb(100, 80, 200);

// text
pub const TEXT_PRIMARY: Color = Color::Rgb(200, 190, 220);
pub const TEXT_DIM: Color = Color::Rgb(120, 100, 150);
pub const TEXT_BRIGHT: Color = Color::Rgb(240, 235, 255);

// accents
pub const ACCENT_BLUE: Color = Color::Rgb(80, 140, 255);
pub const ACCENT_PURPLE: Color = Color::Rgb(160, 100, 255);
pub const ACCENT_YELLOW: Color = Color::Rgb(255, 220, 80);
pub const ACCENT_GREEN: Color = Color::Rgb(80, 220, 120);
pub const ACCENT_RED: Color = Color::Rgb(255, 80, 80);

// protocols
pub const PROTO_FTP: Color = Color::Rgb(255, 180, 80);
pub const PROTO_HTTP: Color = Color::Rgb(80, 180, 255);
pub const PROTO_TELNET: Color = Color::Rgb(255, 120, 120);
pub const PROTO_DNS: Color = Color::Rgb(160, 120, 255);
pub const PROTO_OTHER: Color = Color::Rgb(180, 180, 180);

pub fn title_style() -> Style {
    Style::default()
        .fg(ACCENT_YELLOW)
        .add_modifier(Modifier::BOLD)
}

pub fn header_style() -> Style {
    Style::default()
        .fg(ACCENT_BLUE)
        .add_modifier(Modifier::BOLD)
}

pub fn panel_border() -> Style {
    Style::default().fg(BORDER_DIM)
}

pub fn active_border() -> Style {
    Style::default().fg(BORDER_ACTIVE)
}

pub fn text_normal() -> Style {
    Style::default().fg(TEXT_PRIMARY)
}

pub fn text_dim() -> Style {
    Style::default().fg(TEXT_DIM)
}

pub fn text_bright() -> Style {
    Style::default().fg(TEXT_BRIGHT)
}

pub fn cred_style() -> Style {
    Style::default()
        .fg(ACCENT_YELLOW)
        .add_modifier(Modifier::BOLD)
}

pub fn kill_style() -> Style {
    Style::default()
        .fg(ACCENT_RED)
        .add_modifier(Modifier::BOLD)
}

pub fn success_style() -> Style {
    Style::default().fg(ACCENT_GREEN)
}

pub fn selected_style() -> Style {
    Style::default()
        .bg(BG_HIGHLIGHT)
        .fg(TEXT_BRIGHT)
}

pub fn proto_color(proto: &str) -> Color {
    match proto.to_lowercase().as_str() {
        "ftp" => PROTO_FTP,
        "http-basic" | "http-post" | "http" => PROTO_HTTP,
        "telnet" => PROTO_TELNET,
        "dns" => PROTO_DNS,
        "smtp" | "pop3" | "imap" => PROTO_FTP,
        _ => PROTO_OTHER,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proto_color_known_protocols() {
        assert_eq!(proto_color("ftp"), PROTO_FTP);
        assert_eq!(proto_color("http"), PROTO_HTTP);
        assert_eq!(proto_color("http-basic"), PROTO_HTTP);
        assert_eq!(proto_color("http-post"), PROTO_HTTP);
        assert_eq!(proto_color("telnet"), PROTO_TELNET);
        assert_eq!(proto_color("dns"), PROTO_DNS);
        assert_eq!(proto_color("smtp"), PROTO_FTP);
        assert_eq!(proto_color("pop3"), PROTO_FTP);
        assert_eq!(proto_color("imap"), PROTO_FTP);
    }

    #[test]
    fn test_proto_color_unknown_fallback() {
        assert_eq!(proto_color("ssh"), PROTO_OTHER);
        assert_eq!(proto_color("anything"), PROTO_OTHER);
    }

    #[test]
    fn test_proto_color_case_insensitive() {
        assert_eq!(proto_color("FTP"), proto_color("ftp"));
        assert_eq!(proto_color("HTTP"), proto_color("http"));
        assert_eq!(proto_color("Telnet"), proto_color("telnet"));
    }

    #[test]
    fn test_style_functions_return_styles() {
        let _ = title_style();
        let _ = header_style();
        let _ = panel_border();
        let _ = active_border();
        let _ = text_normal();
        let _ = text_dim();
        let _ = text_bright();
        let _ = cred_style();
        let _ = kill_style();
        let _ = success_style();
        let _ = selected_style();
    }
}
