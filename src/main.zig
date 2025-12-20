const std = @import("std");
const zap = @import("zap");
const auth = @import("auth.zig");

// User structure
const User = struct {
    id: u32,
    email: []const u8,
    password_hash: []const u8,
    name: []const u8,
};

// Task now has user_id
const Task = struct {
    id: u32,
    title: []const u8,
    completed: bool,
    user_id: u32,
};

var users: std.ArrayListUnmanaged(User) = .empty;
var tasks: std.ArrayListUnmanaged(Task) = .empty;
var next_user_id: u32 = 1;
var next_task_id: u32 = 1;
var allocator: std.mem.Allocator = undefined;

pub fn main() !void {
    allocator = std.heap.page_allocator;
    defer users.deinit(allocator);
    defer tasks.deinit(allocator);

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
        const id_str = path[11..];
        const id = std.fmt.parseInt(u32, id_str, 10) catch {
            r.setStatus(.bad_request);
            try r.sendBody("{\"error\": \"Invalid ID\"}");
            return;
        };

        if (r.method) |method| {
            if (std.mem.eql(u8, method, "PUT")) {
                try toggleTask(r, id);
            } else if (std.mem.eql(u8, method, "DELETE")) {
                try deleteTask(r, id);
            }
        }
    } else {
        r.setStatus(.not_found);
        try r.sendBody("{\"error\": \"Not found\"}");
    }
}

// Get current user from Authorization header
fn getCurrentUser(r: zap.Request) ?*const User {
    const auth_header = r.getHeader("authorization") orelse return null;
    
    // Expect "Bearer <token>"
    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) return null;
    const token = auth_header[7..];
    
    const user_id_str = auth.validateToken(allocator, token) catch return null;
    if (user_id_str) |uid_str| {
        const user_id = std.fmt.parseInt(u32, uid_str, 10) catch return null;
        
        for (users.items) |*user| {
            if (user.id == user_id) {
                return user;
            }
        }
    }
    return null;
}

fn handleSignup(r: zap.Request) !void {
    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"No body\"}");
        return;
    };

    // Parse email
    const email = parseJsonField(body, "email") orelse {
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

    // Check if email exists
    for (users.items) |user| {
        if (std.mem.eql(u8, user.email, email)) {
            r.setStatus(.bad_request);
            try r.sendBody("{\"error\": \"Email already exists\"}");
            return;
        }
    }

    // Hash password
    const password_hash = try auth.hashPassword(allocator, password);

    // Create user
    const user = User{
        .id = next_user_id,
        .email = try allocator.dupe(u8, email),
        .password_hash = password_hash,
        .name = try allocator.dupe(u8, name),
    };
    next_user_id += 1;

    try users.append(allocator, user);

    // Create token
    const user_id_str = try std.fmt.allocPrint(allocator, "{d}", .{user.id});
    defer allocator.free(user_id_str);
    const token = try auth.createToken(allocator, user_id_str);

    var response: [512]u8 = undefined;
    const len = (std.fmt.bufPrint(&response, "{{\"token\":\"{s}\",\"user\":{{\"id\":{d},\"email\":\"{s}\",\"name\":\"{s}\"}}}}", .{
        token,
        user.id,
        user.email,
        user.name,
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

    const email = parseJsonField(body, "email") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing email\"}");
        return;
    };

    const password = parseJsonField(body, "password") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\": \"Missing password\"}");
        return;
    };

    // Find user
    for (users.items) |user| {
        if (std.mem.eql(u8, user.email, email)) {
            // Verify password
            const valid = auth.verifyPassword(allocator, user.password_hash, password) catch false;
            if (valid) {
                const user_id_str = try std.fmt.allocPrint(allocator, "{d}", .{user.id});
                defer allocator.free(user_id_str);
                const token = try auth.createToken(allocator, user_id_str);

                var response: [512]u8 = undefined;
                const len = (std.fmt.bufPrint(&response, "{{\"token\":\"{s}\",\"user\":{{\"id\":{d},\"email\":\"{s}\",\"name\":\"{s}\"}}}}", .{
                    token,
                    user.id,
                    user.email,
                    user.name,
                }) catch &response).len;

                r.setStatus(.ok);
                try r.sendBody(response[0..len]);
                return;
            }
        }
    }

    r.setStatus(.unauthorized);
    try r.sendBody("{\"error\": \"Invalid credentials\"}");
}

fn handleMe(r: zap.Request) !void {
    const user = getCurrentUser(r) orelse {
        r.setStatus(.unauthorized);
        try r.sendBody("{\"error\": \"Not authenticated\"}");
        return;
    };

    var response: [256]u8 = undefined;
    const len = (std.fmt.bufPrint(&response, "{{\"id\":{d},\"email\":\"{s}\",\"name\":\"{s}\"}}", .{
        user.id,
        user.email,
        user.name,
    }) catch &response).len;

    r.setStatus(.ok);
    try r.sendBody(response[0..len]);
}

fn getTasks(r: zap.Request) !void {
    const user = getCurrentUser(r);
    
    // Anonymous users get empty array - frontend uses localStorage for them
    if (user == null) {
        r.setStatus(.ok);
        try r.sendBody("[]");
        return;
    }
    
    const user_id = user.?.id;

    var json = std.ArrayListUnmanaged(u8){};
    defer json.deinit(allocator);

    try json.appendSlice(allocator, "[");
    var first = true;
    for (tasks.items) |task| {
        // Only show tasks belonging to this user
        if (task.user_id == user_id) {
            if (!first) try json.appendSlice(allocator, ",");
            first = false;
            try std.fmt.format(json.writer(allocator), "{{\"id\":{d},\"title\":\"{s}\",\"completed\":{}}}", .{
                task.id,
                task.title,
                task.completed,
            });
        }
    }
    try json.appendSlice(allocator, "]");

    r.setStatus(.ok);
    try r.sendBody(json.items);
}

fn createTask(r: zap.Request) !void {
    const user = getCurrentUser(r) orelse {
        // Anonymous users should use localStorage, not API
        r.setStatus(.unauthorized);
        try r.sendBody("{\"error\": \"Login required to save tasks\", \"useLocal\": true}");
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

    const task = Task{
        .id = next_task_id,
        .title = try allocator.dupe(u8, title),
        .completed = false,
        .user_id = user.id,
    };
    next_task_id += 1;

    try tasks.append(allocator, task);

    var response: [256]u8 = undefined;
    const len = (std.fmt.bufPrint(&response, "{{\"id\":{d},\"title\":\"{s}\",\"completed\":false}}", .{
        task.id,
        task.title,
    }) catch &response).len;

    r.setStatus(.created);
    try r.sendBody(response[0..len]);
}

fn toggleTask(r: zap.Request, id: u32) !void {
    for (tasks.items) |*task| {
        if (task.id == id) {
            task.completed = !task.completed;

            var response: [256]u8 = undefined;
            const len = (std.fmt.bufPrint(&response, "{{\"id\":{d},\"title\":\"{s}\",\"completed\":{}}}", .{
                task.id,
                task.title,
                task.completed,
            }) catch &response).len;

            r.setStatus(.ok);
            try r.sendBody(response[0..len]);
            return;
        }
    }

    r.setStatus(.not_found);
    try r.sendBody("{\"error\": \"Task not found\"}");
}

fn deleteTask(r: zap.Request, id: u32) !void {
    for (tasks.items, 0..) |task, i| {
        if (task.id == id) {
            allocator.free(task.title);
            _ = tasks.orderedRemove(i);

            r.setStatus(.ok);
            try r.sendBody("{\"success\": true}");
            return;
        }
    }

    r.setStatus(.not_found);
    try r.sendBody("{\"error\": \"Task not found\"}");
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
