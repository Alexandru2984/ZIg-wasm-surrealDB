const std = @import("std");
const zap = @import("zap");
const auth = @import("auth.zig");
const email = @import("email.zig");
const db = @import("db.zig");

// User structure with profile and verification fields
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

// Task structure
const Task = struct {
    id: u32,
    title: []const u8,
    completed: bool = false,
    user_id: []const u8,  // String ID for SurrealDB
};

// Global allocator
var allocator: std.mem.Allocator = undefined;

pub fn main() !void {
    allocator = std.heap.page_allocator;

    // Initialize SurrealDB schema
    db.initSchema(allocator) catch |err| {
        std.debug.print("⚠️ Could not initialize DB schema: {} (continuing anyway)\n", .{err});
    };

    var listener = zap.HttpListener.init(.{
        .port = 9000,
        .on_request = handleRequest,
        .log = true,
    });
    try listener.listen();

    std.debug.print("\n🦎 Task Manager with Auth running at http://localhost:9000\n\n", .{});

    zap.start(.{
        .threads = 2,
        .workers = 1,
    });
}

fn handleRequest(r: zap.Request) anyerror!void {
    const path = r.path orelse "/";

    if (std.mem.startsWith(u8, path, "/api/")) {
        try handleApi(r, path);
    } else {
        try serveStatic(r, path);
    }
}

fn handleApi(r: zap.Request, path: []const u8) !void {
    r.setHeader("Content-Type", "application/json") catch {};
    r.setHeader("Access-Control-Allow-Origin", "*") catch {};
    r.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS") catch {};
    r.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization") catch {};

    if (r.method) |method| {
        if (std.mem.eql(u8, method, "OPTIONS")) {
            r.setStatus(.ok);
            r.sendBody("") catch {};
            return;
        }
    }

    // Auth routes (no auth required)
    if (std.mem.eql(u8, path, "/api/auth/signup")) {
        try handleSignup(r);
        return;
    } else if (std.mem.eql(u8, path, "/api/auth/login")) {
        try handleLogin(r);
        return;
    } else if (std.mem.eql(u8, path, "/api/auth/me")) {
        try handleMe(r);
        return;
    } else if (std.mem.eql(u8, path, "/api/auth/forgot-password")) {
        try handleForgotPassword(r);
        return;
    } else if (std.mem.eql(u8, path, "/api/auth/reset-password")) {
        try handleResetPassword(r);
        return;
    } else if (std.mem.startsWith(u8, path, "/api/auth/verify")) {
        try handleVerifyEmail(r);
        return;
    }

    // Profile routes (auth required)
    if (std.mem.eql(u8, path, "/api/profile")) {
        if (r.method) |method| {
            if (std.mem.eql(u8, method, "GET")) {
                try getProfile(r);
            } else if (std.mem.eql(u8, method, "PUT")) {
                try updateProfile(r);
            }
        }
        return;
    } else if (std.mem.eql(u8, path, "/api/profile/password")) {
        try changePassword(r);
        return;
    }

    // Task routes
    if (std.mem.eql(u8, path, "/api/tasks")) {
        if (r.method) |method| {
            if (std.mem.eql(u8, method, "GET")) {
                try getTasks(r);
            } else if (std.mem.eql(u8, method, "POST")) {
                try createTask(r);
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
                try toggleTask(r, task_id);
            } else if (std.mem.eql(u8, method, "DELETE")) {
                try deleteTask(r, task_id);
            }
        }
    } else {
        r.setStatus(.not_found);
        try r.sendBody("{\"error\": \"Not found\"}");
    }
}

// Get current user ID from Authorization header
fn getCurrentUserId(r: zap.Request) ?[]const u8 {
    const auth_header = r.getHeader("authorization") orelse return null;
    
    // Expect "Bearer <token>"
    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) return null;
    const token = auth_header[7..];
    
    const user_id_str = auth.validateToken(allocator, token) catch return null;
    return user_id_str;
}

fn handleSignup(r: zap.Request) !void {
    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"No body\"}");
        return;
    };

    // Parse email
    const user_email = parseJsonField(body, "email") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing email\"}");
        return;
    };

    // Parse password
    const password = parseJsonField(body, "password") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing password\"}");
        return;
    };

    // Parse name
    const name = parseJsonField(body, "name") orelse "User";

    // Check if email exists in SurrealDB
    if (db.getUserByEmail(allocator, user_email)) |result| {
        defer allocator.free(result);
        if (std.mem.indexOf(u8, result, "email")) |_| {
            r.setStatus(.bad_request);
            try r.sendBody("{\"error\": \"Email already exists\"}");
            return;
        }
    } else |_| {}

    // Hash password
    const password_hash = try auth.hashPassword(allocator, password);

    // Generate verification code (6 digits)
    const verification_code = try auth.generateVerificationCode(allocator);
    std.debug.print("DEBUG: Verification code for {s}: {s}\n", .{user_email, verification_code});

    // Create user in SurrealDB
    const db_result = db.createUser(allocator, user_email, password_hash, name, verification_code) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Failed to create user\"}");
        return;
    };
    defer allocator.free(db_result);
    
    // Extract user ID from DB result
    const user_id = parseJsonField(db_result, "id") orelse "unknown";
    std.debug.print("✅ User created in DB: {s}\n", .{user_id});

    // Send confirmation email
    email.sendConfirmationEmail(allocator, user_email, name, verification_code) catch |err| {
        std.debug.print("Failed to send confirmation email: {}\n", .{err});
    };

    // Create login token using DB user ID
    const token = try auth.createToken(allocator, user_id);

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

fn handleLogin(r: zap.Request) !void {
    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"No body\"}");
        return;
    };

    const login_email = parseJsonField(body, "email") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing email\"}");
        return;
    };

    const password = parseJsonField(body, "password") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing password\"}");
        return;
    };

    // Query SurrealDB for user
    const db_result = db.getUserByEmail(allocator, login_email) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Database error\"}");
        return;
    };
    defer allocator.free(db_result);
    
    // Check if user exists and verify password
    if (parseJsonField(db_result, "password_hash")) |stored_hash| {
        const valid = auth.verifyPassword(allocator, stored_hash, password) catch false;
        if (valid) {
            const user_id = parseJsonField(db_result, "id") orelse "unknown";
            const user_name = parseJsonField(db_result, "name") orelse "User";
            const token = try auth.createToken(allocator, user_id);
            
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

fn handleMe(r: zap.Request) !void {
    const user_id = getCurrentUserId(r) orelse {
        r.setStatus(.unauthorized);
        try r.sendBody("{\"error\": \"Not authenticated\"}");
        return;
    };

    // Query user from DB
    const db_result = db.getUserById(allocator, user_id) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Database error\"}");
        return;
    };
    defer allocator.free(db_result);
    
    const user_email = parseJsonField(db_result, "email") orelse "unknown";
    const user_name = parseJsonField(db_result, "name") orelse "User";
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

fn getTasks(r: zap.Request) !void {
    const user_id = getCurrentUserId(r) orelse {
        r.setStatus(.ok);
        try r.sendBody("[]");
        return;
    };

    // Query tasks from SurrealDB
    const db_result = db.getTasksByUser(allocator, user_id) catch {
        r.setStatus(.ok);
        try r.sendBody("[]");
        return;
    };
    defer allocator.free(db_result);
    
    // Extract result array from DB response
    if (std.mem.indexOf(u8, db_result, "\"result\":[")) |start| {
        const result_start = start + 10;
        if (std.mem.indexOf(u8, db_result[result_start..], "]")) |end| {
            var json = std.ArrayListUnmanaged(u8){};
            defer json.deinit(allocator);
            try json.appendSlice(allocator, "[");
            try json.appendSlice(allocator, db_result[result_start..result_start + end]);
            try json.appendSlice(allocator, "]");
            r.setStatus(.ok);
            try r.sendBody(json.items);
            return;
        }
    }
    
    r.setStatus(.ok);
    try r.sendBody("[]");
}

fn createTask(r: zap.Request) !void {
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

    const title = parseJsonField(body, "title") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing title\"}");
        return;
    };

    // Check if due_date is provided
    const due_date = parseJsonField(body, "due_date");
    
    // Create task in SurrealDB (with or without due_date)
    const db_result = if (due_date) |dd|
        db.createTaskWithDueDate(allocator, user_id, title, dd) catch {
            r.setStatus(.internal_server_error);
            try r.sendBody("{\"error\": \"Failed to create task\"}");
            return;
        }
    else
        db.createTask(allocator, user_id, title) catch {
            r.setStatus(.internal_server_error);
            try r.sendBody("{\"error\": \"Failed to create task\"}");
            return;
        };
    defer allocator.free(db_result);
    
    const task_id = parseJsonField(db_result, "id") orelse "unknown";
    const created_at = parseJsonField(db_result, "created_at") orelse "";
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

fn toggleTask(r: zap.Request, task_id: []const u8) !void {
    const db_result = db.toggleTask(allocator, task_id) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Failed to toggle task\"}");
        return;
    };
    defer allocator.free(db_result);
    
    const completed = std.mem.indexOf(u8, db_result, "\"completed\":true") != null;
    const title = parseJsonField(db_result, "title") orelse "Task";
    
    var response: [256]u8 = undefined;
    const len = (std.fmt.bufPrint(&response, "{{\"id\":\"{s}\",\"title\":\"{s}\",\"completed\":{}}}", .{
        task_id,
        title,
        completed,
    }) catch &response).len;

    r.setStatus(.ok);
    try r.sendBody(response[0..len]);
}

fn deleteTask(r: zap.Request, task_id: []const u8) !void {
    _ = db.deleteTask(allocator, task_id) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Failed to delete task\"}");
        return;
    };

    r.setStatus(.ok);
    try r.sendBody("{\"success\": true}");
}

fn parseJsonField(body: []const u8, field: []const u8) ?[]const u8 {
    var search_buf: [64]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\":\"", .{field}) catch return null;
    
    const start = std.mem.indexOf(u8, body, search) orelse return null;
    const content_start = start + search.len;
    const end = std.mem.indexOfPos(u8, body, content_start, "\"") orelse return null;
    
    return body[content_start..end];
}

fn serveStatic(r: zap.Request, path: []const u8) !void {
    const file_path = if (std.mem.eql(u8, path, "/"))
        "public/index.html"
    else blk: {
        var buf: [256]u8 = undefined;
        const p = std.fmt.bufPrint(&buf, "public{s}", .{path}) catch "public/index.html";
        break :blk p;
    };

    const ext = std.fs.path.extension(file_path);
    const content_type = if (std.mem.eql(u8, ext, ".html"))
        "text/html"
    else if (std.mem.eql(u8, ext, ".css"))
        "text/css"
    else if (std.mem.eql(u8, ext, ".js"))
        "application/javascript"
    else if (std.mem.eql(u8, ext, ".wasm"))
        "application/wasm"
    else
        "application/octet-stream";

    r.setHeader("Content-Type", content_type) catch {};

    const cwd = std.fs.cwd();
    const file = cwd.openFile(file_path, .{}) catch {
        r.setStatus(.not_found);
        try r.sendBody("404 Not Found");
        return;
    };
    defer file.close();

    const stat = try file.stat();
    const content = try allocator.alloc(u8, stat.size);
    defer allocator.free(content);

    _ = try file.readAll(content);

    r.setStatus(.ok);
    try r.sendBody(content);
}

// ============== PROFILE HANDLERS ==============

fn getProfile(r: zap.Request) !void {
    const user_id = getCurrentUserId(r) orelse {
        r.setStatus(.unauthorized);
        try r.sendBody("{\"error\": \"Not authenticated\"}");
        return;
    };

    // Query user from DB
    const db_result = db.getUserById(allocator, user_id) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Database error\"}");
        return;
    };
    defer allocator.free(db_result);
    
    const user_email = parseJsonField(db_result, "email") orelse "unknown";
    const user_name = parseJsonField(db_result, "name") orelse "User";
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

fn updateProfile(r: zap.Request) !void {
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
    if (parseJsonField(body, "name")) |new_name| {
        if (db.updateUserName(allocator, user_id, new_name)) |result| {
            allocator.free(result);
        } else |_| {}
    }

    // Query updated user
    const db_result = db.getUserById(allocator, user_id) catch {
        r.setStatus(.ok);
        try r.sendBody("{\"success\": true}");
        return;
    };
    defer allocator.free(db_result);
    
    const user_email = parseJsonField(db_result, "email") orelse "unknown";
    const user_name = parseJsonField(db_result, "name") orelse "User";
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

fn changePassword(r: zap.Request) !void {
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

    const current_password = parseJsonField(body, "current") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing current password\"}");
        return;
    };

    const new_password = parseJsonField(body, "new") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing new password\"}");
        return;
    };

    // Get current user from DB to verify password
    const db_result = db.getUserById(allocator, user_id) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Database error\"}");
        return;
    };
    defer allocator.free(db_result);
    
    const stored_hash = parseJsonField(db_result, "password_hash") orelse {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\": \"Could not verify password\"}");
        return;
    };

    // Verify current password
    const valid = auth.verifyPassword(allocator, stored_hash, current_password) catch false;
    if (!valid) {
        r.setStatus(.unauthorized);
        try r.sendBody("{\"error\": \"Current password is incorrect\"}");
        return;
    }

    // Update password in DB
    const new_hash = try auth.hashPassword(allocator, new_password);
    defer allocator.free(new_hash);
    
    if (db.updateUserPassword(allocator, user_id, new_hash)) |result| {
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

fn handleVerifyEmail(r: zap.Request) !void {
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

    const code = parseJsonField(body, "code") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing code\"}");
        return;
    };

    // Find user with this verification code in DB
    const db_result = db.getUserByVerificationToken(allocator, code) catch {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Invalid code\"}");
        return;
    };
    defer allocator.free(db_result);
    
    // Check if user found
    if (parseJsonField(db_result, "id")) |user_id| {
        // Update user as verified
        if (db.updateUserVerified(allocator, user_id)) |result| {
            allocator.free(result);
            r.setStatus(.ok);
            try r.sendBody("{\"success\": true, \"message\": \"Email verified!\"}");
            return;
        } else |_| {}
    }

    r.setStatus(.bad_request);
    try r.sendBody("{\"error\": \"Invalid or expired code\"}");
}

// ============== PASSWORD RESET ==============

fn handleForgotPassword(r: zap.Request) !void {
    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"No body\"}");
        return;
    };

    const user_email = parseJsonField(body, "email") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing email\"}");
        return;
    };

    // Find user in DB
    if (db.getUserByEmail(allocator, user_email)) |db_result| {
        defer allocator.free(db_result);
        
        if (parseJsonField(db_result, "id")) |user_id| {
            // Generate reset token
            const reset_token = try auth.createToken(allocator, "reset");
            const expires = std.time.timestamp() + 3600;
            
            // Save token to DB
            if (db.setResetToken(allocator, user_id, reset_token, expires)) |result| {
                allocator.free(result);
                
                // Send reset email
                email.sendPasswordResetEmail(allocator, user_email, reset_token) catch |err| {
                    std.debug.print("Failed to send reset email: {}\n", .{err});
                };
            } else |_| {}
        }
    } else |_| {}

    // Always return success to prevent email enumeration
    r.setStatus(.ok);
    try r.sendBody("{\"success\": true, \"message\": \"If email exists, reset link sent\"}");
}

fn handleResetPassword(r: zap.Request) !void {
    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"No body\"}");
        return;
    };

    const token = parseJsonField(body, "token") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing token\"}");
        return;
    };

    const new_password = parseJsonField(body, "password") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing password\"}");
        return;
    };

    // Find user with this reset token in DB
    const db_result = db.getUserByResetToken(allocator, token) catch {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Invalid token\"}");
        return;
    };
    defer allocator.free(db_result);
    
    if (parseJsonField(db_result, "id")) |user_id| {
        // Hash new password and update
        const new_hash = try auth.hashPassword(allocator, new_password);
        defer allocator.free(new_hash);
        
        if (db.updateUserPassword(allocator, user_id, new_hash)) |result| {
            allocator.free(result);
            r.setStatus(.ok);
            try r.sendBody("{\"success\": true}");
            return;
        } else |_| {}
    }

    r.setStatus(.bad_request);
    try r.sendBody("{\"error\": \"Invalid or expired token\"}");
}
