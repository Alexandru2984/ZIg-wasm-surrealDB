// SurrealDB Client Module for Zig Task Manager
// Uses HTTP REST API to communicate with SurrealDB

const std = @import("std");

// Database config struct
const DbConfig = struct {
    url: []const u8,
    ns: []const u8,
    db: []const u8,
    user: []const u8,
    pass: []const u8,
};

// Global config
var db_config: ?DbConfig = null;
var config_loaded = false;

pub fn loadConfig(allocator: std.mem.Allocator) !DbConfig {
    if (config_loaded) {
        return db_config orelse error.ConfigNotLoaded;
    }

    const file = std.fs.cwd().openFile("db_settings.txt", .{}) catch |err| {
        std.debug.print("❌ Cannot open db_settings.txt: {}\n", .{err});
        return err;
    };
    defer file.close();

    var buf: [2048]u8 = undefined;
    const len = file.readAll(&buf) catch |err| {
        std.debug.print("❌ Cannot read db_settings.txt: {}\n", .{err});
        return err;
    };

    const content = buf[0..len];

    var url: ?[]const u8 = null;
    var ns: ?[]const u8 = null;
    var db: ?[]const u8 = null;
    var user: ?[]const u8 = null;
    var pass: ?[]const u8 = null;

    var lines = std.mem.splitSequence(u8, content, "\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
            const k = std.mem.trim(u8, trimmed[0..eq_pos], " ");
            const v = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " ");

            if (std.mem.eql(u8, k, "SURREAL_URL")) {
                url = try allocator.dupe(u8, v);
            } else if (std.mem.eql(u8, k, "SURREAL_NS")) {
                ns = try allocator.dupe(u8, v);
            } else if (std.mem.eql(u8, k, "SURREAL_DB")) {
                db = try allocator.dupe(u8, v);
            } else if (std.mem.eql(u8, k, "SURREAL_USER")) {
                user = try allocator.dupe(u8, v);
            } else if (std.mem.eql(u8, k, "SURREAL_PASS")) {
                pass = try allocator.dupe(u8, v);
            }
        }
    }

    if (url == null or ns == null or db == null or user == null or pass == null) {
        std.debug.print("❌ Missing required DB config values\n", .{});
        return error.InvalidConfig;
    }

    db_config = DbConfig{
        .url = url.?,
        .ns = ns.?,
        .db = db.?,
        .user = user.?,
        .pass = pass.?,
    };
    config_loaded = true;

    std.debug.print("✅ SurrealDB config loaded: {s}\n", .{url.?});
    return db_config.?;
}

// Execute a SurrealQL query using curl
pub fn query(allocator: std.mem.Allocator, sql: []const u8) ![]u8 {
    const config = try loadConfig(allocator);

    // Build curl command
    const curl_cmd = try std.fmt.allocPrint(allocator,
        \\curl -s -X POST "{s}/sql" -H "Accept: application/json" -H "surreal-ns: {s}" -H "surreal-db: {s}" -u "{s}:{s}" --data-raw '{s}'
    , .{ config.url, config.ns, config.db, config.user, config.pass, sql });
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
    ;

    const tasks_result = try query(allocator, tasks_schema);
    defer allocator.free(tasks_result);

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
        \\CREATE tasks SET user_id = "{s}", title = "{s}", completed = false;
    , .{ user_id, title });
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
