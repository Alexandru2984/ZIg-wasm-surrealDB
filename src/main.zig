const std = @import("std");
const zap = @import("zap");
const app = @import("app.zig");
const auth = @import("services/auth.zig");
const email = @import("services/email.zig");
const db = @import("db/db.zig");
const validation = @import("util/validation.zig");
const json_helper = @import("util/json.zig");
const config = @import("config/config.zig");
const log = @import("util/log.zig");
const rate_limiter = @import("util/rate_limiter.zig");

// user profile with verification
const User = struct {
    id: u32,
    email: []const u8,
    password_hash: []const u8,
    name: []const u8,
    avatar: ?[]const u8 = null,
    email_verified: bool = false,
    verification_token: ?[]const u8 = null,
    reset_token: ?[]const u8 = null,
    reset_expires: ?i64 = null,
};

// task structure
const Task = struct {
    id: u32,
    title: []const u8,
    completed: bool = false,
    user_id: []const u8,  // String ID for SurrealDB
};

// Global allocator (will use GPA from app module)
var allocator: std.mem.Allocator = undefined;
var app_start_time: i64 = 0;

pub fn main() !void {
    // Initialize app with GPA allocator
    try app.init();
    defer app.deinit(); // Clean shutdown with leak detection
    
    allocator = app.allocator();
    app_start_time = std.time.timestamp();

    // Initialize SurrealDB schema
    db.initSchema(allocator) catch |err| {
        log.warn("Could not initialize DB schema: {} (continuing anyway)", .{err});
    };
    
    // Initialize rate limiters
    rate_limiter.initAll(allocator);
    defer rate_limiter.deinitAll();

    var listener = zap.HttpListener.init(.{
        .port = 9000,
        .interface = "127.0.0.1", // SECURITY: Only allow local connections (via Nginx)
        .on_request = handleRequest,
        .log = true,
    });
    try listener.listen();

    log.banner("Task Manager", 9000);

    zap.start(.{
        .threads = 2,
        .workers = 1,
    });
}

fn handleRequest(r: zap.Request) anyerror!void {
    // Create request-scoped arena - automatically cleaned up at end of request
    var arena = app.createRequestArena();
    defer arena.deinit();
    const req_alloc = arena.allocator();
    
    // Generate unique request ID for tracing
    var request_id_buf: [16]u8 = undefined;
    std.crypto.random.bytes(&request_id_buf);
    const hex_chars = "0123456789abcdef";
    var request_id: [32]u8 = undefined;
    for (request_id_buf, 0..) |byte, i| {
        request_id[i * 2] = hex_chars[byte >> 4];
        request_id[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    r.setHeader("X-Request-ID", &request_id) catch {};
    
    const path = r.path orelse "/";

    if (std.mem.startsWith(u8, path, "/api/")) {
        try handleApi(r, path, req_alloc);
    } else {
        try serveStatic(r, path, req_alloc);
    }
}

fn handleApi(r: zap.Request, path: []const u8, req_alloc: std.mem.Allocator) !void {
    r.setHeader("Content-Type", "application/json") catch {};
    
    // SECURITY: CORS origin from .env config (defaults to * for development)
    const cors_origin = config.getOrDefault("CORS_ORIGIN", "*");
    r.setHeader("Access-Control-Allow-Origin", cors_origin) catch {};
    r.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS") catch {};
    r.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization") catch {};
    r.setHeader("Access-Control-Allow-Credentials", "true") catch {};
    
    // SECURITY: Additional security headers
    r.setHeader("X-Content-Type-Options", "nosniff") catch {};
    r.setHeader("X-Frame-Options", "DENY") catch {};
    r.setHeader("Referrer-Policy", "strict-origin-when-cross-origin") catch {};
    r.setHeader("X-XSS-Protection", "1; mode=block") catch {};

    if (r.method) |method| {
        if (std.mem.eql(u8, method, "OPTIONS")) {
            r.setStatus(.ok);
            r.sendBody("") catch {};
            return;
        }
    }

    // Health check endpoint - always 200 if process is up (no auth)
    if (std.mem.eql(u8, path, "/api/health")) {
        try handleHealth(r, req_alloc);
        return;
    }
    
    // Ready check endpoint - verifies DB connection (no auth)
    if (std.mem.eql(u8, path, "/api/ready")) {
        try handleReady(r, req_alloc);
        return;
    }
    
    // Metrics endpoint for observability (no auth)
    if (std.mem.eql(u8, path, "/api/metrics")) {
        try handleMetrics(r, req_alloc);
        return;
    }

    // Auth routes (no auth required)
    if (std.mem.eql(u8, path, "/api/auth/signup")) {
        try handleSignup(r, req_alloc);
        return;
    } else if (std.mem.eql(u8, path, "/api/auth/login")) {
        try handleLogin(r, req_alloc);
        return;
    } else if (std.mem.eql(u8, path, "/api/auth/me")) {
        try handleMe(r, req_alloc);
        return;
    } else if (std.mem.eql(u8, path, "/api/auth/forgot-password")) {
        try handleForgotPassword(r, req_alloc);
        return;
    } else if (std.mem.eql(u8, path, "/api/auth/reset-password")) {
        try handleResetPassword(r, req_alloc);
        return;
    } else if (std.mem.startsWith(u8, path, "/api/auth/verify")) {
        try handleVerifyEmail(r, req_alloc);
        return;
    }

    // Profile routes (auth required)
    if (std.mem.eql(u8, path, "/api/profile")) {
        if (r.method) |method| {
            if (std.mem.eql(u8, method, "GET")) {
                try getProfile(r, req_alloc);
            } else if (std.mem.eql(u8, method, "PUT")) {
                try updateProfile(r, req_alloc);
            }
        }
        return;
    } else if (std.mem.eql(u8, path, "/api/profile/password")) {
        try changePassword(r, req_alloc);
        return;
    }

    // Task routes
    if (std.mem.eql(u8, path, "/api/tasks")) {
        if (r.method) |method| {
            if (std.mem.eql(u8, method, "GET")) {
                try getTasks(r, req_alloc);
            } else if (std.mem.eql(u8, method, "POST")) {
                try createTask(r, req_alloc);
            }
        }
    } else if (std.mem.startsWith(u8, path, "/api/tasks/")) {
        const task_id = path[11..];  // String ID for SurrealDB
        if (task_id.len == 0) {
            r.setStatus(.bad_request);
            try r.sendBody("{\"error\": \"Invalid ID\"}");
            return;
        }

        if (r.method) |method| {
            if (std.mem.eql(u8, method, "PUT")) {
                try toggleTask(r, task_id, req_alloc);
            } else if (std.mem.eql(u8, method, "DELETE")) {
                try deleteTask(r, task_id, req_alloc);
            }
        }
    } else {
        r.setStatus(.not_found);
        try r.sendBody("{\"error\": \"Not found\"}");
    }
}

// Get current user ID from Authorization header using secure session validation
fn getCurrentUserId(r: zap.Request) ?[]const u8 {
    const auth_header = r.getHeader("authorization") orelse return null;
    
    // Expect "Bearer <token>"
    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) return null;
    const token = auth_header[7..];
    
    // Validate session token in database
    const user_id = db.validateSession(allocator, token) catch return null;
    return user_id;
}

// Get client IP for rate limiting (supports X-Real-IP from Nginx)
fn getClientIp(r: zap.Request) []const u8 {
    // Check for Nginx forwarded IP first
    if (r.getHeader("x-real-ip")) |ip| return ip;
    if (r.getHeader("x-forwarded-for")) |forwarded| {
        // X-Forwarded-For can have multiple IPs, take the first one
        if (std.mem.indexOf(u8, forwarded, ",")) |comma| {
            return forwarded[0..comma];
        }
        return forwarded;
    }
    // Fallback to default (connection IP would need raw socket access)
    return "127.0.0.1";
}

// Health check endpoint - always 200 if process is up
fn handleHealth(r: zap.Request, req_alloc: std.mem.Allocator) !void {
    _ = req_alloc;
    r.setStatus(.ok);
    try r.sendBody("{\"status\":\"healthy\"}");
}

// Ready check endpoint - verifies DB connection and config
fn handleReady(r: zap.Request, req_alloc: std.mem.Allocator) !void {
    // Check DB connectivity
    const db_ok = blk: {
        _ = db.query(req_alloc, "INFO FOR DB;") catch break :blk false;
        break :blk true;
    };
    
    // Check config
    const config_ok = app.isConfigLoaded();
    
    const ready = db_ok and config_ok;
    const status = if (ready) "ready" else "not_ready";
    const db_status = if (db_ok) "connected" else "disconnected";
    
    var response_buf: [256]u8 = undefined;
    const response = std.fmt.bufPrint(&response_buf, 
        \\{{"status":"{s}","database":"{s}","config_loaded":{s}}}
    , .{ status, db_status, if (config_ok) "true" else "false" }) catch {
        try r.sendBody("{\"status\":\"error\"}");
        return;
    };
    
    if (ready) {
        r.setStatus(.ok);
    } else {
        r.setStatus(.service_unavailable);
    }
    try r.sendBody(response);
}

// Metrics endpoint for observability (Prometheus-compatible format)
fn handleMetrics(r: zap.Request, req_alloc: std.mem.Allocator) !void {
    _ = req_alloc;
    
    // Basic metrics - in production, these would track actual counters
    const uptime = std.time.timestamp() - app_start_time;
    
    var metrics_buf: [1024]u8 = undefined;
    const metrics = std.fmt.bufPrint(&metrics_buf,
        \\# HELP app_uptime_seconds Application uptime in seconds
        \\# TYPE app_uptime_seconds counter
        \\app_uptime_seconds {d}
        \\
        \\# HELP app_info Application info
        \\# TYPE app_info gauge
        \\app_info{{version="1.0.0"}} 1
        \\
    , .{uptime}) catch {
        try r.sendBody("# Error generating metrics");
        return;
    };
    
    r.setHeader("Content-Type", "text/plain; version=0.0.4") catch {};
    r.setStatus(.ok);
    try r.sendBody(metrics);
}

fn handleSignup(r: zap.Request, req_alloc: std.mem.Allocator) !void {
    // SECURITY: Rate limiting - 3 signups per minute per IP
    const client_ip = getClientIp(r);
    if (rate_limiter.signup_limiter) |*limiter| {
        if (!limiter.isAllowed(client_ip)) {
            r.setStatus(.too_many_requests);
            r.setHeader("Retry-After", "60") catch {};
            try r.sendBody("{\"error\": \"Too many signup attempts. Please wait 1 minute.\"}");
            return;
        }
    }
    
    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"No body\"}");
        return;
    };

    // Parse email
    const user_email = parseJsonField(req_alloc, body, "email") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing email\"}");
        return;
    };
    
    // SECURITY: Validate email format
    if (!validation.validateEmail(user_email)) {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Invalid email format\"}");
        return;
    }

    // Parse password
    const password = parseJsonField(req_alloc, body, "password") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing password\"}");
        return;
    };
    
    // SECURITY: Validate password strength
    const pwd_result = validation.validatePasswordStrength(password);
    if (!pwd_result.valid) {
        r.setStatus(.bad_request);
        if (pwd_result.too_short) {
            try r.sendBody("{\"error\": \"Password must be at least 8 characters\"}");
        } else {
            try r.sendBody("{\"error\": \"Password is too long\"}");
        }
        return;
    }

    // Parse name
    const name = parseJsonField(req_alloc, body, "name") orelse "User";
    
    // SECURITY: Validate name
    if (!validation.validateName(name)) {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Invalid name format\"}");
        return;
    }

    // Check if email exists in SurrealDB
    if (db.getUserByEmail(req_alloc, user_email)) |result| {
        if (std.mem.indexOf(u8, result, "email")) |_| {
            r.setStatus(.bad_request);
            try r.sendBody("{\"error\": \"Email already exists\"}");
            return;
        }
    } else |_| {}

    // Hash password
    const password_hash = try auth.hashPassword(req_alloc, password);

    // Generate verification code (6 digits)
    // SECURITY: Code is sent via email only, never logged
    const verification_code = try auth.generateVerificationCode(req_alloc);

    // Create user in SurrealDB with 10-minute verification code expiration
    const verification_expires = std.time.timestamp() + 600; // 10 minutes
    const db_result = db.createUser(req_alloc, user_email, password_hash, name, verification_code, verification_expires) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Failed to create user\"}");
        return;
    };
    
    // Extract user ID from DB result
    const user_id = parseJsonField(req_alloc, db_result, "id") orelse "unknown";
    std.debug.print("✅ User created in DB: {s}\n", .{user_id});

    // Send confirmation email
    email.sendConfirmationEmail(req_alloc, user_email, name, verification_code) catch |err| {
        std.debug.print("Failed to send confirmation email: {}\n", .{err});
    };

    // Create secure session token (stored in DB)
    const token = db.createSession(req_alloc, user_id) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Failed to create session\"}");
        return;
    };

    var response: [512]u8 = undefined;
    const len = (std.fmt.bufPrint(&response, "{{\"token\":\"{s}\",\"user\":{{\"id\":\"{s}\",\"email\":\"{s}\",\"name\":\"{s}\",\"email_verified\":false}}}}", .{
        token,
        user_id,
        user_email,
        name,
    }) catch &response).len;

    r.setStatus(.created);
    try r.sendBody(response[0..len]);
}

fn handleLogin(r: zap.Request, req_alloc: std.mem.Allocator) !void {
    // SECURITY: Rate limiting - 5 attempts per minute per IP
    const client_ip = getClientIp(r);
    if (rate_limiter.login_limiter) |*limiter| {
        if (!limiter.isAllowed(client_ip)) {
            r.setStatus(.too_many_requests);
            r.setHeader("Retry-After", "60") catch {};
            try r.sendBody("{\"error\": \"Too many login attempts. Please wait 1 minute.\"}");
            return;
        }
    }
    
    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"No body\"}");
        return;
    };

    const login_email = parseJsonField(req_alloc, body, "email") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing email\"}");
        return;
    };

    const password = parseJsonField(req_alloc, body, "password") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing password\"}");
        return;
    };

    // Query SurrealDB for user
    const db_result = db.getUserByEmail(req_alloc, login_email) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Database error\"}");
        return;
    };
    
    // Check if user exists and verify password
    if (parseJsonField(req_alloc, db_result, "password_hash")) |stored_hash| {
        const valid = auth.verifyPassword(req_alloc, stored_hash, password) catch false;
        if (valid) {
            const user_id = parseJsonField(req_alloc, db_result, "id") orelse "unknown";
            const user_name = parseJsonField(req_alloc, db_result, "name") orelse "User";
            
            // Create secure session token (stored in DB)
            const token = db.createSession(req_alloc, user_id) catch {
                r.setStatus(.internal_server_error);
                try r.sendBody("{\"error\": \"Failed to create session\"}");
                return;
            };
            
            var response: [512]u8 = undefined;
            const len = (std.fmt.bufPrint(&response, "{{\"token\":\"{s}\",\"user\":{{\"id\":\"{s}\",\"email\":\"{s}\",\"name\":\"{s}\"}}}}", .{
                token,
                user_id,
                login_email,
                user_name,
            }) catch &response).len;
            
            r.setStatus(.ok);
            try r.sendBody(response[0..len]);
            return;
        }
    }

    r.setStatus(.unauthorized);
    try r.sendBody("{\"error\": \"Invalid credentials\"}");
}

fn handleMe(r: zap.Request, req_alloc: std.mem.Allocator) !void {
    const user_id = getCurrentUserId(r) orelse {
        r.setStatus(.unauthorized);
        try r.sendBody("{\"error\": \"Not authenticated\"}");
        return;
    };

    // Query user from DB
    const db_result = db.getUserById(req_alloc, user_id) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Database error\"}");
        return;
    };
    
    const user_email = parseJsonField(req_alloc, db_result, "email") orelse "unknown";
    const user_name = parseJsonField(req_alloc, db_result, "name") orelse "User";
    const email_verified = std.mem.indexOf(u8, db_result, "\"email_verified\":true") != null;

    var response: [512]u8 = undefined;
    const len = (std.fmt.bufPrint(&response, "{{\"id\":\"{s}\",\"email\":\"{s}\",\"name\":\"{s}\",\"email_verified\":{}}}", .{
        user_id,
        user_email,
        user_name,
        email_verified,
    }) catch &response).len;

    r.setStatus(.ok);
    try r.sendBody(response[0..len]);
}

fn getTasks(r: zap.Request, req_alloc: std.mem.Allocator) !void {
    const user_id = getCurrentUserId(r) orelse {
        r.setStatus(.ok);
        try r.sendBody("[]");
        return;
    };

    // Query tasks from SurrealDB
    const db_result = db.getTasksByUser(req_alloc, user_id) catch {
        r.setStatus(.ok);
        try r.sendBody("[]");
        return;
    };
    
    // Extract result array from DB response
    if (std.mem.indexOf(u8, db_result, "\"result\":[")) |start| {
        const result_start = start + 10;
        if (std.mem.indexOf(u8, db_result[result_start..], "]")) |end| {
            var json = std.ArrayListUnmanaged(u8){};
            defer json.deinit(req_alloc);
            try json.appendSlice(req_alloc, "[");
            try json.appendSlice(req_alloc, db_result[result_start..result_start + end]);
            try json.appendSlice(req_alloc, "]");
            r.setStatus(.ok);
            try r.sendBody(json.items);
            return;
        }
    }
    
    r.setStatus(.ok);
    try r.sendBody("[]");
}

fn createTask(r: zap.Request, req_alloc: std.mem.Allocator) !void {
    const user_id = getCurrentUserId(r) orelse {
        r.setStatus(.unauthorized);
        try r.sendBody("{\"error\": \"Login required\", \"useLocal\": true}");
        return;
    };

    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"No body\"}");
        return;
    };

    const title = parseJsonField(req_alloc, body, "title") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing title\"}");
        return;
    };

    // Check if due_date is provided
    const due_date = parseJsonField(req_alloc, body, "due_date");
    
    // Create task in SurrealDB (with or without due_date)
    const db_result = if (due_date) |dd|
        db.createTaskWithDueDate(req_alloc, user_id, title, dd) catch {
            r.setStatus(.internal_server_error);
            try r.sendBody("{\"error\": \"Failed to create task\"}");
            return;
        }
    else
        db.createTask(req_alloc, user_id, title) catch {
            r.setStatus(.internal_server_error);
            try r.sendBody("{\"error\": \"Failed to create task\"}");
            return;
        };
    
    const task_id = parseJsonField(req_alloc, db_result, "id") orelse "unknown";
    const created_at = parseJsonField(req_alloc, db_result, "created_at") orelse "";
    std.debug.print("✅ Task created: {s}\n", .{task_id});

    var response: [512]u8 = undefined;
    if (due_date) |dd| {
        const len = (std.fmt.bufPrint(&response, "{{\"id\":\"{s}\",\"title\":\"{s}\",\"completed\":false,\"created_at\":\"{s}\",\"due_date\":\"{s}\"}}", .{
            task_id,
            title,
            created_at,
            dd,
        }) catch &response).len;
        r.setStatus(.created);
        try r.sendBody(response[0..len]);
    } else {
        const len = (std.fmt.bufPrint(&response, "{{\"id\":\"{s}\",\"title\":\"{s}\",\"completed\":false,\"created_at\":\"{s}\"}}", .{
            task_id,
            title,
            created_at,
        }) catch &response).len;
        r.setStatus(.created);
        try r.sendBody(response[0..len]);
    }
}

fn toggleTask(r: zap.Request, task_id: []const u8, req_alloc: std.mem.Allocator) !void {
    // SECURITY: Verify ownership before toggling
    const user_id = getCurrentUserId(r) orelse {
        r.setStatus(.unauthorized);
        try r.sendBody("{\"error\": \"Unauthorized\"}");
        return;
    };
    
    // Check if this task belongs to the current user
    const is_owner = db.verifyTaskOwnership(req_alloc, task_id, user_id) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Failed to verify ownership\"}");
        return;
    };
    
    if (!is_owner) {
        r.setStatus(.forbidden);
        try r.sendBody("{\"error\": \"Forbidden: not your task\"}");
        return;
    }
    
    const db_result = db.toggleTask(req_alloc, task_id) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Failed to toggle task\"}");
        return;
    };
    
    const completed = std.mem.indexOf(u8, db_result, "\"completed\":true") != null;
    const title = parseJsonField(req_alloc, db_result, "title") orelse "Task";
    
    var response: [256]u8 = undefined;
    const len = (std.fmt.bufPrint(&response, "{{\"id\":\"{s}\",\"title\":\"{s}\",\"completed\":{}}}", .{
        task_id,
        title,
        completed,
    }) catch &response).len;

    r.setStatus(.ok);
    try r.sendBody(response[0..len]);
}

fn deleteTask(r: zap.Request, task_id: []const u8, req_alloc: std.mem.Allocator) !void {
    // SECURITY: Verify ownership before deleting
    const user_id = getCurrentUserId(r) orelse {
        r.setStatus(.unauthorized);
        try r.sendBody("{\"error\": \"Unauthorized\"}");
        return;
    };
    
    // Check if this task belongs to the current user
    const is_owner = db.verifyTaskOwnership(req_alloc, task_id, user_id) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Failed to verify ownership\"}");
        return;
    };
    
    if (!is_owner) {
        r.setStatus(.forbidden);
        try r.sendBody("{\"error\": \"Forbidden: not your task\"}");
        return;
    }
    
    _ = db.deleteTask(req_alloc, task_id) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Failed to delete task\"}");
        return;
    };

    r.setStatus(.ok);
    try r.sendBody("{\"success\": true}");
}

// JSON field parser using proper std.json (handles spaces, escapes, field order)
// NOTE: With arena allocator, no need to manually free the returned memory
fn parseJsonField(alloc: std.mem.Allocator, body: []const u8, field: []const u8) ?[]const u8 {
    // Use proper JSON parsing from json.zig helper
    return json_helper.parseRequestBody(alloc, body, field);
}

fn serveStatic(r: zap.Request, path: []const u8, req_alloc: std.mem.Allocator) !void {
    // SECURITY: Block path traversal attacks
    if (std.mem.indexOf(u8, path, "..") != null) {
        std.debug.print("🚫 Path traversal blocked: {s}\n", .{path});
        r.setStatus(.forbidden);
        try r.sendBody("403 Forbidden");
        return;
    }
    
    // SECURITY: Block hidden files and sensitive paths
    if (std.mem.startsWith(u8, path, "/.") or 
        std.mem.indexOf(u8, path, "/.") != null or
        std.mem.eql(u8, path, "/db_settings.txt") or
        std.mem.eql(u8, path, "/mail_settings.txt")) {
        std.debug.print("🚫 Hidden/sensitive file blocked: {s}\n", .{path});
        r.setStatus(.not_found);
        try r.sendBody("404 Not Found");
        return;
    }

    const file_path = if (std.mem.eql(u8, path, "/"))
        "public/index.html"
    else blk: {
        var buf: [256]u8 = undefined;
        const p = std.fmt.bufPrint(&buf, "public{s}", .{path}) catch "public/index.html";
        break :blk p;
    };
    
    // SECURITY: Verify resolved path stays within public directory
    const cwd = std.fs.cwd();
    const real_path = cwd.realpathAlloc(req_alloc, file_path) catch {
        r.setStatus(.not_found);
        try r.sendBody("404 Not Found");
        return;
    };
    
    const public_base = cwd.realpathAlloc(req_alloc, "public") catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("500 Server Error");
        return;
    };
    
    // Ensure file is within public directory
    if (!std.mem.startsWith(u8, real_path, public_base)) {
        std.debug.print("🚫 Path escape blocked: {s} not in {s}\n", .{real_path, public_base});
        r.setStatus(.forbidden);
        try r.sendBody("403 Forbidden");
        return;
    }

    const ext = std.fs.path.extension(file_path);
    const content_type = if (std.mem.eql(u8, ext, ".html"))
        "text/html"
    else if (std.mem.eql(u8, ext, ".css"))
        "text/css"
    else if (std.mem.eql(u8, ext, ".js"))
        "application/javascript"
    else if (std.mem.eql(u8, ext, ".wasm"))
        "application/wasm"
    else if (std.mem.eql(u8, ext, ".png"))
        "image/png"
    else if (std.mem.eql(u8, ext, ".jpg") or std.mem.eql(u8, ext, ".jpeg"))
        "image/jpeg"
    else if (std.mem.eql(u8, ext, ".svg"))
        "image/svg+xml"
    else if (std.mem.eql(u8, ext, ".ico"))
        "image/x-icon"
    else
        "application/octet-stream";

    r.setHeader("Content-Type", content_type) catch {};
    
    // SECURITY: Add security headers for static files
    r.setHeader("X-Content-Type-Options", "nosniff") catch {};
    r.setHeader("X-Frame-Options", "SAMEORIGIN") catch {};
    r.setHeader("Referrer-Policy", "strict-origin-when-cross-origin") catch {};
    
    // Add CSP for HTML pages only
    if (std.mem.eql(u8, ext, ".html")) {
        r.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://task.micutu.com") catch {};
    }

    const file = cwd.openFile(file_path, .{}) catch {
        r.setStatus(.not_found);
        try r.sendBody("404 Not Found");
        return;
    };
    defer file.close();

    const stat = try file.stat();
    const content = try allocator.alloc(u8, stat.size);

    _ = try file.readAll(content);

    // Cache-Control: no-cache for HTML, 1 hour for assets
    if (std.mem.eql(u8, ext, ".html")) {
        r.setHeader("Cache-Control", "no-cache, must-revalidate") catch {};
    } else {
        r.setHeader("Cache-Control", "public, max-age=3600") catch {};
    }

    r.setStatus(.ok);
    try r.sendBody(content);
}

// ============== PROFILE HANDLERS ==============

fn getProfile(r: zap.Request, req_alloc: std.mem.Allocator) !void {
    const user_id = getCurrentUserId(r) orelse {
        r.setStatus(.unauthorized);
        try r.sendBody("{\"error\": \"Not authenticated\"}");
        return;
    };

    // Query user from DB
    const db_result = db.getUserById(req_alloc, user_id) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Database error\"}");
        return;
    };
    
    const user_email = parseJsonField(req_alloc, db_result, "email") orelse "unknown";
    const user_name = parseJsonField(req_alloc, db_result, "name") orelse "User";
    const email_verified = std.mem.indexOf(u8, db_result, "\"email_verified\":true") != null;

    var response: [512]u8 = undefined;
    const len = (std.fmt.bufPrint(&response, "{{\"id\":\"{s}\",\"email\":\"{s}\",\"name\":\"{s}\",\"avatar\":null,\"email_verified\":{}}}", .{
        user_id,
        user_email,
        user_name,
        email_verified,
    }) catch &response).len;

    r.setStatus(.ok);
    try r.sendBody(response[0..len]);
}

fn updateProfile(r: zap.Request, req_alloc: std.mem.Allocator) !void {
    const user_id = getCurrentUserId(r) orelse {
        r.setStatus(.unauthorized);
        try r.sendBody("{\"error\": \"Not authenticated\"}");
        return;
    };

    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"No body\"}");
        return;
    };

    // Update name if provided
    if (parseJsonField(req_alloc, body, "name")) |new_name| {
        if (db.updateUserName(req_alloc, user_id, new_name)) |result| {
            allocator.free(result);
        } else |_| {}
    }

    // Query updated user
    const db_result = db.getUserById(req_alloc, user_id) catch {
        r.setStatus(.ok);
        try r.sendBody("{\"success\": true}");
        return;
    };
    
    const user_email = parseJsonField(req_alloc, db_result, "email") orelse "unknown";
    const user_name = parseJsonField(req_alloc, db_result, "name") orelse "User";
    const email_verified = std.mem.indexOf(u8, db_result, "\"email_verified\":true") != null;

    var response: [512]u8 = undefined;
    const len = (std.fmt.bufPrint(&response, "{{\"id\":\"{s}\",\"email\":\"{s}\",\"name\":\"{s}\",\"avatar\":null,\"email_verified\":{}}}", .{
        user_id,
        user_email,
        user_name,
        email_verified,
    }) catch &response).len;

    r.setStatus(.ok);
    try r.sendBody(response[0..len]);
}

fn changePassword(r: zap.Request, req_alloc: std.mem.Allocator) !void {
    const user_id = getCurrentUserId(r) orelse {
        r.setStatus(.unauthorized);
        try r.sendBody("{\"error\": \"Not authenticated\"}");
        return;
    };

    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"No body\"}");
        return;
    };

    const current_password = parseJsonField(req_alloc, body, "current") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing current password\"}");
        return;
    };

    const new_password = parseJsonField(req_alloc, body, "new") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing new password\"}");
        return;
    };

    // Get current user from DB to verify password
    const db_result = db.getUserById(req_alloc, user_id) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Database error\"}");
        return;
    };
    
    const stored_hash = parseJsonField(req_alloc, db_result, "password_hash") orelse {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Could not verify password\"}");
        return;
    };

    // Verify current password
    const valid = auth.verifyPassword(req_alloc, stored_hash, current_password) catch false;
    if (!valid) {
        r.setStatus(.unauthorized);
        try r.sendBody("{\"error\": \"Current password is incorrect\"}");
        return;
    }

    // Update password in DB
    const new_hash = try auth.hashPassword(req_alloc, new_password);
    
    if (db.updateUserPassword(req_alloc, user_id, new_hash)) |result| {
        allocator.free(result);
    } else |_| {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Failed to update password\"}");
        return;
    }

    r.setStatus(.ok);
    try r.sendBody("{\"success\": true}");
}

fn getCurrentUserMutable(r: zap.Request) ?[]const u8 {
    // Now returns user_id string instead of mutable pointer
    return getCurrentUserId(r);
}

// ============== EMAIL VERIFICATION ==============

fn handleVerifyEmail(r: zap.Request, req_alloc: std.mem.Allocator) !void {
    if (r.method) |m| {
        if (!std.mem.eql(u8, m, "POST")) {
            r.setStatus(.method_not_allowed);
            try r.sendBody("{\"error\": \"Method not allowed\"}");
            return;
        }
    }

    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"No body\"}");
        return;
    };

    const code = parseJsonField(req_alloc, body, "code") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing code\"}");
        return;
    };

    // Find user with this verification code in DB
    const db_result = db.getUserByVerificationToken(req_alloc, code) catch {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Invalid code\"}");
        return;
    };
    
    // Check if user found
    if (parseJsonField(req_alloc, db_result, "id")) |user_id| {
        // Check if code has expired
        if (parseJsonField(req_alloc, db_result, "verification_expires")) |expires_str| {
            const expires = std.fmt.parseInt(i64, expires_str, 10) catch 0;
            const now = std.time.timestamp();
            if (now > expires) {
                r.setStatus(.bad_request);
                try r.sendBody("{\"error\": \"Verification code has expired. Please request a new one.\"}");
                return;
            }
        }
        
        // Update user as verified (arena handles cleanup)
        if (db.updateUserVerified(req_alloc, user_id)) |_| {
            r.setStatus(.ok);
            try r.sendBody("{\"success\": true, \"message\": \"Email verified!\"}");
            return;
        } else |_| {}
    }

    r.setStatus(.bad_request);
    try r.sendBody("{\"error\": \"Invalid or expired code\"}");
}

// ============== PASSWORD RESET ==============

fn handleForgotPassword(r: zap.Request, req_alloc: std.mem.Allocator) !void {
    // SECURITY: Rate limiting - 3 password reset requests per minute per IP
    const client_ip = getClientIp(r);
    if (rate_limiter.forgot_password_limiter) |*limiter| {
        if (!limiter.isAllowed(client_ip)) {
            r.setStatus(.too_many_requests);
            r.setHeader("Retry-After", "60") catch {};
            try r.sendBody("{\"error\": \"Too many password reset requests. Please wait 1 minute.\"}");
            return;
        }
    }
    
    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"No body\"}");
        return;
    };

    const user_email = parseJsonField(req_alloc, body, "email") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing email\"}");
        return;
    };

    // Find user in DB
    if (db.getUserByEmail(req_alloc, user_email)) |db_result| {
        
        if (parseJsonField(req_alloc, db_result, "id")) |user_id| {
            // Generate reset token
            const reset_token = try auth.createToken(req_alloc, "reset");
            const expires = std.time.timestamp() + 3600;
            
            // Save token to DB
            if (db.setResetToken(req_alloc, user_id, reset_token, expires)) |_| {
                // Arena will clean up - no manual free needed
                
                // Send reset email
                email.sendPasswordResetEmail(req_alloc, user_email, reset_token) catch |err| {
                    std.debug.print("Failed to send reset email: {}\n", .{err});
                };
            } else |_| {
            }
        } else {
        }
    } else |_| {
    }

    // Always return success to prevent email enumeration
    r.setStatus(.ok);
    try r.sendBody("{\"success\": true, \"message\": \"If email exists, reset link sent\"}");
}

fn handleResetPassword(r: zap.Request, req_alloc: std.mem.Allocator) !void {
    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"No body\"}");
        return;
    };

    const token = parseJsonField(req_alloc, body, "token") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing token\"}");
        return;
    };

    const new_password = parseJsonField(req_alloc, body, "password") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing password\"}");
        return;
    };

    // Find user with this reset token in DB
    const db_result = db.getUserByResetToken(req_alloc, token) catch {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Invalid token\"}");
        return;
    };
    
    if (parseJsonField(req_alloc, db_result, "id")) |user_id| {
        // Hash new password and update
        const new_hash = try auth.hashPassword(req_alloc, new_password);
        
        if (db.updateUserPassword(req_alloc, user_id, new_hash)) |result| {
            allocator.free(result);
            r.setStatus(.ok);
            try r.sendBody("{\"success\": true}");
            return;
        } else |_| {}
    }

    r.setStatus(.bad_request);
    try r.sendBody("{\"error\": \"Invalid or expired token\"}");
}
