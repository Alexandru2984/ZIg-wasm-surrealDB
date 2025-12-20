// Email module for Task Manager - Native Zig HTTP Implementation
// Uses std.http.Client to send emails via Brevo HTTP API
// No external dependencies (curl not needed)

const std = @import("std");

// API config struct
const EmailConfig = struct {
    api_key: []const u8,
    from_email: []const u8,
    from_name: []const u8,
};

// Global config
var email_config: ?EmailConfig = null;
var config_loaded = false;

fn loadConfig(allocator: std.mem.Allocator) !EmailConfig {
    if (config_loaded) {
        return email_config orelse error.ConfigNotLoaded;
    }

    const file = std.fs.cwd().openFile("mail_settings.txt", .{}) catch |err| {
        std.debug.print("❌ Cannot open mail_settings.txt: {}\n", .{err});
        return err;
    };
    defer file.close();

    var buf: [4096]u8 = undefined;
    const len = file.readAll(&buf) catch |err| {
        std.debug.print("❌ Cannot read mail_settings.txt: {}\n", .{err});
        return err;
    };

    const content = buf[0..len];

    var api_key: ?[]const u8 = null;
    var from_email: ?[]const u8 = null;
    var from_name: ?[]const u8 = null;

    var lines = std.mem.splitSequence(u8, content, "\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
            const k = std.mem.trim(u8, trimmed[0..eq_pos], " ");
            var v = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " ");
            
            // Strip quotes from value if present
            if (v.len >= 2 and v[0] == '"' and v[v.len - 1] == '"') {
                v = v[1..v.len - 1];
            }

            // Accept both BREVO_API_KEY and API_KEY
            if (std.mem.eql(u8, k, "BREVO_API_KEY") or std.mem.eql(u8, k, "API_KEY")) {
                api_key = try allocator.dupe(u8, v);
            } else if (std.mem.eql(u8, k, "SEND_FROM") or std.mem.eql(u8, k, "FROM_EMAIL")) {
                from_email = try allocator.dupe(u8, v);
            } else if (std.mem.eql(u8, k, "FROM_NAME")) {
                from_name = try allocator.dupe(u8, v);
            }
            // Also support old SMTP_LOGIN as fallback for from_email
            else if (from_email == null and std.mem.eql(u8, k, "SMTP_LOGIN")) {
                from_email = try allocator.dupe(u8, v);
            }
        }
    }

    if (api_key == null) {
        std.debug.print("❌ Missing BREVO_API_KEY in mail_settings.txt\n", .{});
        return error.InvalidConfig;
    }

    if (from_email == null) {
        std.debug.print("❌ Missing SEND_FROM or FROM_EMAIL in mail_settings.txt\n", .{});
        return error.InvalidConfig;
    }

    email_config = EmailConfig{
        .api_key = api_key.?,
        .from_email = from_email.?,
        .from_name = from_name orelse "Zig Task Manager",
    };
    config_loaded = true;

    std.debug.print("✅ Email config loaded (Brevo HTTP API)\n", .{});
    return email_config.?;
}

pub fn sendConfirmationEmail(allocator: std.mem.Allocator, to_email: []const u8, name: []const u8, code: []const u8) !void {
    const subject = "Your Verification Code - Zig Task Manager";
    const body = try std.fmt.allocPrint(allocator,
        \\Hello {s},
        \\
        \\Welcome to Zig Task Manager!
        \\
        \\Your verification code is: {s}
        \\
        \\Please enter this code in the application to verify your account.
        \\
        \\Best regards,
        \\Zig Task Manager Team
    , .{ name, code });
    defer allocator.free(body);

    try sendEmail(allocator, to_email, name, subject, body);
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
    const config = try loadConfig(allocator);

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
    , .{ config.from_name, config.from_email, to_email, to_name_str, subject, escaped_buf[0..escaped_len] });
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
            .{ .name = "api-key", .value = config.api_key },
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

