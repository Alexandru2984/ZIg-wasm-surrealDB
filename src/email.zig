// Email module for Task Manager - Native Zig HTTP Implementation
// Uses std.http.Client to send emails via Brevo HTTP API
// No external dependencies (curl not needed)

const std = @import("std");
const config = @import("config.zig");

// API config struct
const EmailConfig = struct {
    api_key: []const u8,
    from_email: []const u8,
    from_name: []const u8,
};

// Get email config from unified .env config
// Supports both old names (API_KEY, SEND_FROM) and new names (BREVO_API_KEY, FROM_EMAIL)
fn getEmailConfig() !EmailConfig {
    // Try new names first, then fall back to old names
    const api_key = config.get("BREVO_API_KEY") orelse config.get("API_KEY") orelse {
        std.debug.print("❌ Missing BREVO_API_KEY or API_KEY in .env\n", .{});
        return error.MissingEmailConfig;
    };
    
    const from_email = config.get("FROM_EMAIL") orelse config.get("SEND_FROM") orelse {
        std.debug.print("❌ Missing FROM_EMAIL or SEND_FROM in .env\n", .{});
        return error.MissingEmailConfig;
    };
    
    return EmailConfig{
        .api_key = api_key,
        .from_email = from_email,
        .from_name = config.getOrDefault("FROM_NAME", "Zig Task Manager"),
    };
}


pub fn sendConfirmationEmail(allocator: std.mem.Allocator, to_email: []const u8, name: []const u8, code: []const u8) !void {
    const subject = "Your Verification Code - Zig Task Manager";
    
    // Beautiful HTML email template
    const html_body = try std.fmt.allocPrint(allocator,
        \\<!DOCTYPE html>
        \\<html>
        \\<head>
        \\  <meta charset="UTF-8">
        \\  <meta name="viewport" content="width=device-width, initial-scale=1.0">
        \\</head>
        \\<body style="margin:0;padding:0;font-family:'Segoe UI',Roboto,Arial,sans-serif;background-color:#1a1a2e;">
        \\  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#1a1a2e;padding:40px 20px;">
        \\    <tr>
        \\      <td align="center">
        \\        <table width="100%" max-width="500" cellpadding="0" cellspacing="0" style="background:linear-gradient(135deg,#16213e 0%,#1a1a2e 100%);border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.3);">
        \\          <!-- Header -->
        \\          <tr>
        \\            <td style="background:linear-gradient(135deg,#f7931a 0%,#f5a623 100%);padding:30px;text-align:center;">
        \\              <h1 style="margin:0;color:#fff;font-size:24px;font-weight:700;">🦎 Zig Task Manager</h1>
        \\            </td>
        \\          </tr>
        \\          <!-- Content -->
        \\          <tr>
        \\            <td style="padding:40px 30px;">
        \\              <h2 style="margin:0 0 20px;color:#fff;font-size:20px;">Hello {s}! 👋</h2>
        \\              <p style="margin:0 0 25px;color:#a0aec0;font-size:16px;line-height:1.6;">Welcome to Zig Task Manager! Please use the verification code below to activate your account:</p>
        \\              <!-- Code Box -->
        \\              <div style="background:#0d1117;border:2px solid #f7931a;border-radius:12px;padding:25px;text-align:center;margin:25px 0;">
        \\                <span style="font-family:monospace;font-size:32px;font-weight:700;color:#f7931a;letter-spacing:8px;">{s}</span>
        \\              </div>
        \\              <p style="margin:25px 0 0;color:#718096;font-size:14px;line-height:1.5;">This code will expire in 10 minutes. If you didn't create an account, you can safely ignore this email.</p>
        \\            </td>
        \\          </tr>
        \\          <!-- Footer -->
        \\          <tr>
        \\            <td style="padding:20px 30px;border-top:1px solid rgba(255,255,255,0.1);text-align:center;">
        \\              <p style="margin:0;color:#4a5568;font-size:12px;">Built with ❤️ using Zig + WASM + SurrealDB</p>
        \\            </td>
        \\          </tr>
        \\        </table>
        \\      </td>
        \\    </tr>
        \\  </table>
        \\</body>
        \\</html>
    , .{ name, code });
    defer allocator.free(html_body);

    try sendHtmlEmail(allocator, to_email, name, subject, html_body);
}

pub fn sendPasswordResetEmail(allocator: std.mem.Allocator, to_email: []const u8, token: []const u8) !void {
    const reset_link = try std.fmt.allocPrint(allocator, "http://localhost:9000/reset-password.html?token={s}", .{token});
    defer allocator.free(reset_link);

    const subject = "Reset your password - Zig Task Manager";
    const body = try std.fmt.allocPrint(allocator,
        \\Hello,
        \\
        \\You requested a password reset for your Zig Task Manager account.
        \\
        \\Click the link below to reset your password:
        \\{s}
        \\
        \\This link will expire in 1 hour.
        \\
        \\If you didn't request this, please ignore this email.
        \\
        \\Best regards,
        \\Zig Task Manager Team
    , .{reset_link});
    defer allocator.free(body);

    try sendEmail(allocator, to_email, "", subject, body);
}

fn sendEmail(allocator: std.mem.Allocator, to_email: []const u8, to_name: []const u8, subject: []const u8, text_content: []const u8) !void {
    const email_cfg = try getEmailConfig();

    std.debug.print("📧 Sending email to: {s} via Brevo API\n", .{to_email});

    // Escape special characters in content for JSON
    var escaped_buf: [8192]u8 = undefined;
    var escaped_len: usize = 0;
    
    for (text_content) |c| {
        if (escaped_len >= escaped_buf.len - 4) break;
        switch (c) {
            '"' => {
                escaped_buf[escaped_len] = '\\';
                escaped_buf[escaped_len + 1] = '"';
                escaped_len += 2;
            },
            '\\' => {
                escaped_buf[escaped_len] = '\\';
                escaped_buf[escaped_len + 1] = '\\';
                escaped_len += 2;
            },
            '\n' => {
                escaped_buf[escaped_len] = '\\';
                escaped_buf[escaped_len + 1] = 'n';
                escaped_len += 2;
            },
            '\r' => {
                escaped_buf[escaped_len] = '\\';
                escaped_buf[escaped_len + 1] = 'r';
                escaped_len += 2;
            },
            '\t' => {
                escaped_buf[escaped_len] = '\\';
                escaped_buf[escaped_len + 1] = 't';
                escaped_len += 2;
            },
            else => {
                escaped_buf[escaped_len] = c;
                escaped_len += 1;
            },
        }
    }

    const to_name_str = if (to_name.len > 0) to_name else "User";
    
    const json_payload = try std.fmt.allocPrint(allocator,
        \\{{"sender":{{"name":"{s}","email":"{s}"}},"to":[{{"email":"{s}","name":"{s}"}}],"subject":"{s}","textContent":"{s}"}}
    , .{ email_cfg.from_name, email_cfg.from_email, to_email, to_name_str, subject, escaped_buf[0..escaped_len] });
    defer allocator.free(json_payload);

    // Use std.http.Client with fetch API
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    // Make request using fetch
    const result = client.fetch(.{
        .location = .{ .url = "https://api.brevo.com/v3/smtp/email" },
        .method = .POST,
        .payload = json_payload,
        .extra_headers = &[_]std.http.Header{
            .{ .name = "api-key", .value = email_cfg.api_key },
            .{ .name = "accept", .value = "application/json" },
            .{ .name = "content-type", .value = "application/json" },
        },
    }) catch |err| {
        std.debug.print("❌ HTTP request failed: {}\n", .{err});
        return error.EmailSendFailed;
    };

    // Check status
    switch (result.status) {
        .ok, .created, .accepted => {
            std.debug.print("✅ Email sent successfully to: {s}\n", .{to_email});
        },
        else => {
            std.debug.print("❌ Brevo API error: HTTP {d}\n", .{@intFromEnum(result.status)});
            return error.EmailSendFailed;
        },
    }
}

fn sendHtmlEmail(allocator: std.mem.Allocator, to_email: []const u8, to_name: []const u8, subject: []const u8, html_content: []const u8) !void {
    const email_cfg = try getEmailConfig();

    std.debug.print("📧 Sending HTML email to: {s} via Brevo API\n", .{to_email});

    // Escape special characters in HTML content for JSON
    var escaped_buf: [16384]u8 = undefined;
    var escaped_len: usize = 0;
    
    for (html_content) |c| {
        if (escaped_len >= escaped_buf.len - 4) break;
        switch (c) {
            '"' => {
                escaped_buf[escaped_len] = '\\';
                escaped_buf[escaped_len + 1] = '"';
                escaped_len += 2;
            },
            '\\' => {
                escaped_buf[escaped_len] = '\\';
                escaped_buf[escaped_len + 1] = '\\';
                escaped_len += 2;
            },
            '\n' => {
                // Skip newlines in HTML (they're not needed)
                escaped_len += 0;
            },
            '\r' => {
                escaped_len += 0;
            },
            '\t' => {
                escaped_buf[escaped_len] = ' ';
                escaped_len += 1;
            },
            else => {
                escaped_buf[escaped_len] = c;
                escaped_len += 1;
            },
        }
    }

    const to_name_str = if (to_name.len > 0) to_name else "User";
    
    const json_payload = try std.fmt.allocPrint(allocator,
        \\{{"sender":{{"name":"{s}","email":"{s}"}},"to":[{{"email":"{s}","name":"{s}"}}],"subject":"{s}","htmlContent":"{s}"}}
    , .{ email_cfg.from_name, email_cfg.from_email, to_email, to_name_str, subject, escaped_buf[0..escaped_len] });
    defer allocator.free(json_payload);

    // Use std.http.Client with fetch API
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    // Make request using fetch
    const result = client.fetch(.{
        .location = .{ .url = "https://api.brevo.com/v3/smtp/email" },
        .method = .POST,
        .payload = json_payload,
        .extra_headers = &[_]std.http.Header{
            .{ .name = "api-key", .value = email_cfg.api_key },
            .{ .name = "accept", .value = "application/json" },
            .{ .name = "content-type", .value = "application/json" },
        },
    }) catch |err| {
        std.debug.print("❌ HTTP request failed: {}\n", .{err});
        return error.EmailSendFailed;
    };

    // Check status
    switch (result.status) {
        .ok, .created, .accepted => {
            std.debug.print("✅ HTML Email sent successfully to: {s}\n", .{to_email});
        },
        else => {
            std.debug.print("❌ Brevo API error: HTTP {d}\n", .{@intFromEnum(result.status)});
            return error.EmailSendFailed;
        },
    }
}
