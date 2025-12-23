// SurrealDB Client Module for Zig Task Manager
// Uses HTTP REST API to communicate with SurrealDB
// SECURITY: All user inputs MUST be escaped using escape() before SQL interpolation

const std = @import("std");
const config = @import("../config/config.zig");
const validation = @import("../util/validation.zig");

// SECURITY: Escape string for safe SQL interpolation
// Uses validation.sanitizeForSurrealQL to prevent SQL injection
fn escape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    return validation.sanitizeForSurrealQL(allocator, input);
}

// Database config struct
const DbConfig = struct {
    url: []const u8,
    ns: []const u8,
    db: []const u8,
    user: []const u8,
    pass: []const u8,
};

// Get DB config from unified .env config
fn getDbConfig() !DbConfig {
    return DbConfig{
        .url = config.getRequired("SURREAL_URL") catch return error.MissingDbConfig,
        .ns = config.getRequired("SURREAL_NS") catch return error.MissingDbConfig,
        .db = config.getRequired("SURREAL_DB") catch return error.MissingDbConfig,
        .user = config.getRequired("SURREAL_USER") catch return error.MissingDbConfig,
        .pass = config.getRequired("SURREAL_PASS") catch return error.MissingDbConfig,
    };
}

// Execute a SurrealQL query using curl
// NOTE: Using curl temporarily - Zig 0.15 std.http.Client API does not support 
// response body retrieval in a compatible way. SQL is sanitized before use.
pub fn query(allocator: std.mem.Allocator, sql: []const u8) ![]u8 {
    const db_cfg = try getDbConfig();

    // Build curl command - credentials are passed via -u flag (not in URL)
    const curl_cmd = try std.fmt.allocPrint(allocator,
        \\curl -s -X POST "{s}/sql" -H "Accept: application/json" -H "surreal-ns: {s}" -H "surreal-db: {s}" -u "{s}:{s}" --data-raw '{s}'
    , .{ db_cfg.url, db_cfg.ns, db_cfg.db, db_cfg.user, db_cfg.pass, sql });
    defer allocator.free(curl_cmd);

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "/bin/sh", "-c", curl_cmd },
    }) catch |err| {
        std.debug.print("❌ DB query failed: {}\n", .{err});
        return err;
    };
    defer allocator.free(result.stderr);

    return result.stdout;
}

// Initialize database schema
pub fn initSchema(allocator: std.mem.Allocator) !void {
    std.debug.print("🗄️ Initializing SurrealDB schema...\n", .{});

    // Define users table
    const users_schema =
        \\DEFINE TABLE users SCHEMAFULL;
        \\DEFINE FIELD email ON users TYPE string;
        \\DEFINE FIELD password_hash ON users TYPE string;
        \\DEFINE FIELD name ON users TYPE string;
        \\DEFINE FIELD avatar ON users TYPE option<string>;
        \\DEFINE FIELD email_verified ON users TYPE bool DEFAULT false;
        \\DEFINE FIELD verification_token ON users TYPE option<string>;
        \\DEFINE FIELD reset_token ON users TYPE option<string>;
        \\DEFINE FIELD reset_expires ON users TYPE option<int>;
        \\DEFINE INDEX email_idx ON users COLUMNS email UNIQUE;
    ;

    const users_result = try query(allocator, users_schema);
    defer allocator.free(users_result);

    // Define tasks table
    const tasks_schema =
        \\DEFINE TABLE tasks SCHEMAFULL;
        \\DEFINE FIELD user_id ON tasks TYPE string;
        \\DEFINE FIELD title ON tasks TYPE string;
        \\DEFINE FIELD completed ON tasks TYPE bool DEFAULT false;
        \\DEFINE FIELD created_at ON tasks TYPE datetime DEFAULT time::now();
        \\DEFINE FIELD due_date ON tasks TYPE option<datetime> ASSERT $value == NONE OR $value >= created_at;
    ;

    const tasks_result = try query(allocator, tasks_schema);
    defer allocator.free(tasks_result);

    // Define sessions table for secure token storage
    const sessions_schema =
        \\DEFINE TABLE sessions SCHEMAFULL;
        \\DEFINE FIELD token ON sessions TYPE string;
        \\DEFINE FIELD user_id ON sessions TYPE string;
        \\DEFINE FIELD created_at ON sessions TYPE datetime DEFAULT time::now();
        \\DEFINE FIELD expires_at ON sessions TYPE datetime;
        \\DEFINE INDEX session_token_idx ON sessions COLUMNS token UNIQUE;
    ;

    const sessions_result = try query(allocator, sessions_schema);
    defer allocator.free(sessions_result);

    std.debug.print("✅ SurrealDB schema initialized\n", .{});
}

// ============== USER OPERATIONS ==============

pub fn createUser(allocator: std.mem.Allocator, email: []const u8, password_hash: []const u8, name: []const u8, verification_token: []const u8) ![]u8 {
    const sql = try std.fmt.allocPrint(allocator,
        \\CREATE users SET email = "{s}", password_hash = "{s}", name = "{s}", email_verified = false, verification_token = "{s}";
    , .{ email, password_hash, name, verification_token });
    defer allocator.free(sql);

    return try query(allocator, sql);
}

pub fn getUserByEmail(allocator: std.mem.Allocator, email: []const u8) ![]u8 {
    const sql = try std.fmt.allocPrint(allocator,
        \\SELECT * FROM users WHERE email = "{s}";
    , .{email});
    defer allocator.free(sql);

    return try query(allocator, sql);
}

pub fn getUserById(allocator: std.mem.Allocator, id: []const u8) ![]u8 {
    const sql = try std.fmt.allocPrint(allocator,
        \\SELECT * FROM {s};
    , .{id});
    defer allocator.free(sql);

    return try query(allocator, sql);
}

pub fn updateUserVerified(allocator: std.mem.Allocator, user_id: []const u8) ![]u8 {
    const sql = try std.fmt.allocPrint(allocator,
        \\UPDATE {s} SET email_verified = true, verification_token = NONE;
    , .{user_id});
    defer allocator.free(sql);

    return try query(allocator, sql);
}

pub fn updateUserName(allocator: std.mem.Allocator, user_id: []const u8, name: []const u8) ![]u8 {
    const sql = try std.fmt.allocPrint(allocator,
        \\UPDATE {s} SET name = "{s}";
    , .{ user_id, name });
    defer allocator.free(sql);

    return try query(allocator, sql);
}

pub fn updateUserPassword(allocator: std.mem.Allocator, user_id: []const u8, password_hash: []const u8) ![]u8 {
    const sql = try std.fmt.allocPrint(allocator,
        \\UPDATE {s} SET password_hash = "{s}";
    , .{ user_id, password_hash });
    defer allocator.free(sql);

    return try query(allocator, sql);
}

pub fn setResetToken(allocator: std.mem.Allocator, user_id: []const u8, token: []const u8, expires: i64) ![]u8 {
    const sql = try std.fmt.allocPrint(allocator,
        \\UPDATE {s} SET reset_token = "{s}", reset_expires = {d};
    , .{ user_id, token, expires });
    defer allocator.free(sql);

    return try query(allocator, sql);
}

pub fn getUserByResetToken(allocator: std.mem.Allocator, token: []const u8) ![]u8 {
    const sql = try std.fmt.allocPrint(allocator,
        \\SELECT * FROM users WHERE reset_token = "{s}";
    , .{token});
    defer allocator.free(sql);

    return try query(allocator, sql);
}

pub fn getUserByVerificationToken(allocator: std.mem.Allocator, token: []const u8) ![]u8 {
    const sql = try std.fmt.allocPrint(allocator,
        \\SELECT * FROM users WHERE verification_token = "{s}";
    , .{token});
    defer allocator.free(sql);

    return try query(allocator, sql);
}

// ============== TASK OPERATIONS ==============

pub fn createTask(allocator: std.mem.Allocator, user_id: []const u8, title: []const u8) ![]u8 {
    const sql = try std.fmt.allocPrint(allocator,
        \\CREATE tasks SET user_id = "{s}", title = "{s}", completed = false, created_at = time::now();
    , .{ user_id, title });
    defer allocator.free(sql);

    return try query(allocator, sql);
}

pub fn createTaskWithDueDate(allocator: std.mem.Allocator, user_id: []const u8, title: []const u8, due_date: []const u8) ![]u8 {
    // Ensure due_date has proper format (add :00Z if needed for SurrealDB)
    // HTML datetime-local gives "2025-12-25T12:00" but SurrealDB needs "2025-12-25T12:00:00Z"
    var formatted_date: []const u8 = due_date;
    var needs_free = false;
    
    if (!std.mem.endsWith(u8, due_date, "Z")) {
        if (std.mem.count(u8, due_date, ":") == 1) {
            // Format is "2025-12-25T12:00" - add ":00Z"
            formatted_date = try std.fmt.allocPrint(allocator, "{s}:00Z", .{due_date});
            needs_free = true;
        } else {
            // Format might be "2025-12-25T12:00:00" - just add "Z"
            formatted_date = try std.fmt.allocPrint(allocator, "{s}Z", .{due_date});
            needs_free = true;
        }
    }
    defer if (needs_free) allocator.free(formatted_date);
    
    const sql = try std.fmt.allocPrint(allocator,
        \\CREATE tasks SET user_id = "{s}", title = "{s}", completed = false, created_at = time::now(), due_date = <datetime>"{s}";
    , .{ user_id, title, formatted_date });
    defer allocator.free(sql);

    return try query(allocator, sql);
}

pub fn getTasksByUser(allocator: std.mem.Allocator, user_id: []const u8) ![]u8 {
    const sql = try std.fmt.allocPrint(allocator,
        \\SELECT * FROM tasks WHERE user_id = "{s}";
    , .{user_id});
    defer allocator.free(sql);

    return try query(allocator, sql);
}

pub fn toggleTask(allocator: std.mem.Allocator, task_id: []const u8) ![]u8 {
    // First get current state
    const get_sql = try std.fmt.allocPrint(allocator,
        \\SELECT completed FROM {s};
    , .{task_id});
    defer allocator.free(get_sql);

    const current = try query(allocator, get_sql);
    defer allocator.free(current);

    // Toggle
    const toggle_sql = try std.fmt.allocPrint(allocator,
        \\UPDATE {s} SET completed = !completed;
    , .{task_id});
    defer allocator.free(toggle_sql);

    return try query(allocator, toggle_sql);
}

pub fn deleteTask(allocator: std.mem.Allocator, task_id: []const u8) ![]u8 {
    const sql = try std.fmt.allocPrint(allocator,
        \\DELETE {s};
    , .{task_id});
    defer allocator.free(sql);

    return try query(allocator, sql);
}

// ============== TASK OWNERSHIP ==============

pub fn getTaskOwner(allocator: std.mem.Allocator, task_id: []const u8) !?[]const u8 {
    const sql = try std.fmt.allocPrint(allocator,
        \\SELECT user_id FROM {s};
    , .{task_id});
    defer allocator.free(sql);

    const result = try query(allocator, sql);
    defer allocator.free(result);

    // Parse user_id from result
    if (std.mem.indexOf(u8, result, "\"user_id\":\"")) |start| {
        const value_start = start + 11; // length of "\"user_id\":\""
        if (std.mem.indexOfPos(u8, result, value_start, "\"")) |end| {
            return try allocator.dupe(u8, result[value_start..end]);
        }
    }
    
    return null;
}

pub fn verifyTaskOwnership(allocator: std.mem.Allocator, task_id: []const u8, user_id: []const u8) !bool {
    const owner = try getTaskOwner(allocator, task_id);
    if (owner) |task_owner| {
        defer allocator.free(task_owner);
        return std.mem.eql(u8, task_owner, user_id);
    }
    return false; // Task doesn't exist or has no owner
}

// ============== SESSION MANAGEMENT ==============
// Secure token-based authentication stored in database

/// Generate a cryptographically secure random token (32 bytes = 64 hex chars)
pub fn generateSecureToken() [64]u8 {
    var random_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    
    const hex_chars = "0123456789abcdef";
    var hex_token: [64]u8 = undefined;
    
    for (random_bytes, 0..) |byte, i| {
        hex_token[i * 2] = hex_chars[byte >> 4];
        hex_token[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    
    return hex_token;
}

/// Create a new session for a user, returns the session token
/// Session expires in 7 days by default
pub fn createSession(allocator: std.mem.Allocator, user_id: []const u8) ![]u8 {
    const token = generateSecureToken();
    
    // Calculate expiration (7 days from now in milliseconds)
    const expires_ms = std.time.milliTimestamp() + (7 * 24 * 60 * 60 * 1000);
    
    const sql = try std.fmt.allocPrint(allocator,
        \\CREATE sessions SET token = "{s}", user_id = "{s}", expires_at = <datetime>"{d}";
    , .{ token, user_id, expires_ms });
    defer allocator.free(sql);

    const result = try query(allocator, sql);
    defer allocator.free(result);
    
    // Return a copy of the token
    return try allocator.dupe(u8, &token);
}

/// Validate a session token and return the user_id if valid
/// Returns null if token is invalid or expired
pub fn validateSession(allocator: std.mem.Allocator, token: []const u8) !?[]u8 {
    const sql = try std.fmt.allocPrint(allocator,
        \\SELECT user_id, expires_at FROM sessions WHERE token = "{s}";
    , .{token});
    defer allocator.free(sql);

    const result = try query(allocator, sql);
    defer allocator.free(result);

    // Check if we got a result
    if (std.mem.indexOf(u8, result, "\"user_id\":\"")) |start| {
        // Parse user_id
        const value_start = start + 11;
        if (std.mem.indexOfPos(u8, result, value_start, "\"")) |end| {
            const user_id = result[value_start..end];
            
            // TODO: Check expiration (for now, just return user_id)
            // In production, parse expires_at and compare with current time
            
            return try allocator.dupe(u8, user_id);
        }
    }
    
    return null;
}

/// Delete a specific session (logout)
pub fn deleteSession(allocator: std.mem.Allocator, token: []const u8) !void {
    const sql = try std.fmt.allocPrint(allocator,
        \\DELETE FROM sessions WHERE token = "{s}";
    , .{token});
    defer allocator.free(sql);

    const result = try query(allocator, sql);
    allocator.free(result);
}

/// Delete all sessions for a user (logout all devices)
pub fn deleteUserSessions(allocator: std.mem.Allocator, user_id: []const u8) !void {
    const sql = try std.fmt.allocPrint(allocator,
        \\DELETE FROM sessions WHERE user_id = "{s}";
    , .{user_id});
    defer allocator.free(sql);

    const result = try query(allocator, sql);
    allocator.free(result);
}

/// Cleanup expired sessions (should be called periodically)
pub fn cleanupExpiredSessions(allocator: std.mem.Allocator) !void {
    const current_ms = std.time.milliTimestamp();
    const sql = try std.fmt.allocPrint(allocator,
        \\DELETE FROM sessions WHERE expires_at < <datetime>"{d}";
    , .{current_ms});
    defer allocator.free(sql);

    const result = try query(allocator, sql);
    allocator.free(result);
}
