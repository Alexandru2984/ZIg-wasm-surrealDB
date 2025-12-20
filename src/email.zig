// Email module for Task Manager - Brevo SMTP Integration
// Uses shell command to send emails via SMTP
// Credentials are loaded from mail_settings.txt

const std = @import("std");

// SMTP settings struct
const SmtpConfig = struct {
    server: []const u8,
    port: []const u8,
    login: []const u8,
    key: []const u8,
    from: []const u8,
};

// Global config (loaded once)
var smtp_config: ?SmtpConfig = null;
var config_loaded = false;

fn loadConfig(allocator: std.mem.Allocator) !SmtpConfig {
    if (config_loaded) {
        return smtp_config orelse error.ConfigNotLoaded;
    }

    const file = std.fs.cwd().openFile("mail_settings.txt", .{}) catch |err| {
        std.debug.print("❌ Cannot open mail_settings.txt: {}\n", .{err});
        return err;
    };
    defer file.close();

    var buf: [2048]u8 = undefined;
    const len = file.readAll(&buf) catch |err| {
        std.debug.print("❌ Cannot read mail_settings.txt: {}\n", .{err});
        return err;
    };

    const content = buf[0..len];
    
    // Parse key=value lines
    var server: ?[]const u8 = null;
    var port: ?[]const u8 = null;
    var login: ?[]const u8 = null;
    var key: ?[]const u8 = null;
    var from: ?[]const u8 = null;

    var lines = std.mem.splitSequence(u8, content, "\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
            const k = std.mem.trim(u8, trimmed[0..eq_pos], " ");
            const v = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " ");

            if (std.mem.eql(u8, k, "SMTP_SERVER")) {
                server = try allocator.dupe(u8, v);
            } else if (std.mem.eql(u8, k, "SMTP_PORT")) {
                port = try allocator.dupe(u8, v);
            } else if (std.mem.eql(u8, k, "SMTP_LOGIN")) {
                login = try allocator.dupe(u8, v);
            } else if (std.mem.eql(u8, k, "SMTP_KEY")) {
                key = try allocator.dupe(u8, v);
            } else if (std.mem.eql(u8, k, "SEND_FROM")) {
                from = try allocator.dupe(u8, v);
            }
        }
    }

    if (server == null or port == null or login == null or key == null or from == null) {
        std.debug.print("❌ Missing required SMTP config values\n", .{});
        return error.InvalidConfig;
    }

    smtp_config = SmtpConfig{
        .server = server.?,
        .port = port.?,
        .login = login.?,
        .key = key.?,
        .from = from.?,
    };
    config_loaded = true;

    std.debug.print("✅ SMTP config loaded from mail_settings.txt\n", .{});
    return smtp_config.?;
}

pub fn sendConfirmationEmail(allocator: std.mem.Allocator, to_email: []const u8, name: []const u8, code: []const u8) !void {
    const subject = "Your Verification Code - Zig Task Manager";
    const body = try std.fmt.allocPrint(allocator,
        \\Hello {s},
        \\
        \\Welcome to Zig Task Manager!
        \\
        \\Your verification code is:
        \\
        \\{s}
        \\
        \\Please enter this code in the application to verify your account.
        \\
        \\Best regards,
        \\Zig Task Manager Team
    , .{ name, code });
    defer allocator.free(body);

    try sendEmail(allocator, to_email, subject, body);
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

    try sendEmail(allocator, to_email, subject, body);
}

fn sendEmail(allocator: std.mem.Allocator, to: []const u8, subject: []const u8, body: []const u8) !void {
    const config = try loadConfig(allocator);
    
    std.debug.print("📧 Preparing email to: {s}\n", .{to});
    
    // Create email content with proper CRLF line endings
    const email_content = try std.fmt.allocPrint(allocator,
        "From: Zig Task Manager <{s}>\r\nTo: {s}\r\nSubject: {s}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{s}",
        .{ config.from, to, subject, body }
    );
    defer allocator.free(email_content);

    // Write to temp file
    const tmp_path = "/tmp/zig_email.txt";
    const file = std.fs.cwd().createFile(tmp_path, .{}) catch |err| {
        std.debug.print("❌ Failed to create temp file: {}\n", .{err});
        return err;
    };
    file.writeAll(email_content) catch |err| {
        std.debug.print("❌ Failed to write to temp file: {}\n", .{err});
        file.close();
        return err;
    };
    file.close();

    // Build the full shell command with output to log file
    const shell_cmd = try std.fmt.allocPrint(allocator,
        \\curl --url "smtp://{s}:{s}" --ssl-reqd --mail-from "{s}" --mail-rcpt "{s}" --user "{s}:{s}" -T "{s}" -v > /tmp/curl_email.log 2>&1
    , .{ config.server, config.port, config.from, to, config.login, config.key, tmp_path });
    defer allocator.free(shell_cmd);

    std.debug.print("🚀 Running curl command...\n", .{});

    // Use system() equivalent
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "/bin/sh", "-c", shell_cmd },
    }) catch |err| {
        std.debug.print("❌ Failed to run command: {}\n", .{err});
        return err;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Read the log file to see what happened
    const log_file = std.fs.cwd().openFile("/tmp/curl_email.log", .{}) catch {
        std.debug.print("⚠️ Could not read curl log\n", .{});
        return;
    };
    defer log_file.close();
    
    var log_buf: [2048]u8 = undefined;
    const log_len = log_file.readAll(&log_buf) catch 0;
    if (log_len > 0) {
        // Check for success indicators
        const log_content = log_buf[0..log_len];
        if (std.mem.indexOf(u8, log_content, "250 2.0.0 OK") != null) {
            std.debug.print("✅ Email sent successfully to: {s}\n", .{to});
        } else if (std.mem.indexOf(u8, log_content, "Authentication succeeded") != null) {
            std.debug.print("✅ Auth OK, email queued to: {s}\n", .{to});
        } else {
            std.debug.print("⚠️ curl output:\n{s}\n", .{log_content});
        }
    }

    // Clean up
    std.fs.cwd().deleteFile(tmp_path) catch {};
}

