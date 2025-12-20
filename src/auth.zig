// Authentication module for Task Manager
const std = @import("std");

// Simple token secret
const SECRET = "zig-task-manager-secret-2024";

pub fn hashPassword(allocator: std.mem.Allocator, password: []const u8) ![]u8 {
    // Simple hash using FNV-1a (not cryptographically secure, but works for demo)
    var hash: u64 = 14695981039346656037;
    for (password) |byte| {
        hash ^= byte;
        hash *%= 1099511628211;
    }
    // Add salt
    for (SECRET) |byte| {
        hash ^= byte;
        hash *%= 1099511628211;
    }
    return try std.fmt.allocPrint(allocator, "{x}", .{hash});
}

pub fn verifyPassword(allocator: std.mem.Allocator, stored_hash: []const u8, password: []const u8) !bool {
    const computed = try hashPassword(allocator, password);
    defer allocator.free(computed);
    return std.mem.eql(u8, stored_hash, computed);
}

pub fn createToken(allocator: std.mem.Allocator, user_id: []const u8) ![]u8 {
    const timestamp = std.time.timestamp();
    // Token format: user_id.timestamp_hex
    return try std.fmt.allocPrint(allocator, "{s}.{x}", .{ user_id, timestamp });
}

pub fn validateToken(allocator: std.mem.Allocator, token: []const u8) !?[]const u8 {
    _ = allocator;
    // Token format: user_id.timestamp_hex
    const dot_pos = std.mem.indexOf(u8, token, ".") orelse return null;
    
    const user_id = token[0..dot_pos];
    const timestamp_hex = token[dot_pos + 1 ..];
    
    // Parse timestamp
    const timestamp = std.fmt.parseInt(i64, timestamp_hex, 16) catch return null;
    const now = std.time.timestamp();
    
    // Token valid for 7 days
    const seven_days: i64 = 7 * 24 * 60 * 60;
    if (now - timestamp > seven_days) {
        return null; // Token expired
    }
    
    return user_id;
}

pub fn generateVerificationCode(allocator: std.mem.Allocator) ![]u8 {
    const code = std.crypto.random.intRangeAtMost(u32, 100000, 999999);
    return try std.fmt.allocPrint(allocator, "{d}", .{code});
}
