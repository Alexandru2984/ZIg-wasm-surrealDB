// Native HTTP Client for SurrealDB
// Replaces shell subprocess (sh -c curl) with direct Zig HTTP
// SECURITY: No more shell injection risk, proper retry

const std = @import("std");
const config = @import("../config/config.zig");

// Retry configuration
const MAX_RETRIES: u8 = 3;
const RETRY_DELAYS_MS = [_]u64{ 200, 500, 1000 }; // 200ms, 500ms, 1s backoff

pub const HttpError = error{
    ConnectionFailed,
    RequestFailed,
    ServerError,
    InvalidResponse,
    ResponseTooLarge,
    MissingConfig,
};

/// Database config
const DbConfig = struct {
    url: []const u8,
    ns: []const u8,
    db: []const u8,
    user: []const u8,
    pass: []const u8,
};

/// Get DB config from .env
fn getDbConfig() !DbConfig {
    return DbConfig{
        .url = config.getRequired("SURREAL_URL") catch return HttpError.MissingConfig,
        .ns = config.getRequired("SURREAL_NS") catch return HttpError.MissingConfig,
        .db = config.getRequired("SURREAL_DB") catch return HttpError.MissingConfig,
        .user = config.getRequired("SURREAL_USER") catch return HttpError.MissingConfig,
        .pass = config.getRequired("SURREAL_PASS") catch return HttpError.MissingConfig,
    };
}

/// Build Basic Auth header value
fn buildAuthHeader(allocator: std.mem.Allocator, user: []const u8, pass: []const u8) ![]u8 {
    // Format: "Basic base64(user:pass)"
    const credentials = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ user, pass });
    defer allocator.free(credentials);
    
    // Use standard base64 encoder
    const encoded_len = std.base64.standard.Encoder.calcSize(credentials.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(encoded, credentials);
    defer allocator.free(encoded);
    
    return try std.fmt.allocPrint(allocator, "Basic {s}", .{encoded});
}

/// Execute SQL query against SurrealDB using native HTTP client
/// Returns owned response body (caller must free)
pub fn executeQuery(allocator: std.mem.Allocator, sql: []const u8) ![]u8 {
    const db_cfg = try getDbConfig();
    
    // Build URL
    const url = try std.fmt.allocPrint(allocator, "{s}/sql", .{db_cfg.url});
    defer allocator.free(url);
    
    // Build auth header
    const auth_header = try buildAuthHeader(allocator, db_cfg.user, db_cfg.pass);
    defer allocator.free(auth_header);
    
    var last_error: ?anyerror = null;
    
    // Retry loop
    var attempt: u8 = 0;
    while (attempt < MAX_RETRIES) : (attempt += 1) {
        // Create fresh client for each attempt
        var client = std.http.Client{ .allocator = allocator };
        defer client.deinit();
        
        // Response writer - allocating
        var response_writer = std.Io.Writer.Allocating.init(allocator);
        defer if (response_writer.writer.buffer.len > 0) allocator.free(response_writer.writer.buffer);
        
        // Use fetch API with response_writer
        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = sql,
            .extra_headers = &[_]std.http.Header{
                .{ .name = "Accept", .value = "application/json" },
                .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
                .{ .name = "Authorization", .value = auth_header },
                .{ .name = "surreal-ns", .value = db_cfg.ns },
                .{ .name = "surreal-db", .value = db_cfg.db },
            },
            .response_writer = &response_writer.writer,
        }) catch |err| {
            last_error = err;
            std.debug.print("⚠️ DB attempt {d}/{d} failed: {}\n", .{ attempt + 1, MAX_RETRIES, err });
            
            if (attempt < MAX_RETRIES - 1) {
                std.Thread.sleep(RETRY_DELAYS_MS[attempt] * std.time.ns_per_ms);
            }
            continue;
        };
        
        // Check status
        const status = result.status;
        if (status == .ok or status == .created or status == .accepted) {
            // Success! Return owned slice (transfer ownership)
            const body = response_writer.writer.buffer;
            response_writer.writer.buffer = &.{}; // Prevent deferred free
            return try allocator.dupe(u8, body);
        } else if (@intFromEnum(status) >= 500) {
            // Server error - retry
            std.debug.print("⚠️ DB attempt {d}/{d}: HTTP {d}\n", .{ attempt + 1, MAX_RETRIES, @intFromEnum(status) });
            last_error = HttpError.ServerError;
            
            if (attempt < MAX_RETRIES - 1) {
                std.Thread.sleep(RETRY_DELAYS_MS[attempt] * std.time.ns_per_ms);
            }
        } else {
            // Client error (4xx) - don't retry
            std.debug.print("❌ DB query error: HTTP {d}\n", .{@intFromEnum(status)});
            const body = response_writer.writer.buffer;
            const preview_len = @min(body.len, 200);
            std.debug.print("   Response: {s}\n", .{body[0..preview_len]});
            return HttpError.RequestFailed;
        }
    }
    
    // All retries exhausted
    std.debug.print("❌ DB query failed after {d} attempts\n", .{MAX_RETRIES});
    return last_error orelse HttpError.ConnectionFailed;
}
