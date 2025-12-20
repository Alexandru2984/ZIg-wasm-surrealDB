// Zig Task Manager - JavaScript with Auth
// Logged users: tasks in DB | Anonymous: tasks in localStorage

let wasm = null;
let wasmMemory = null;
let currentUser = null;

// DOM Elements
const taskForm = document.getElementById('taskForm');
const taskInput = document.getElementById('taskInput');
const taskList = document.getElementById('taskList');
const emptyState = document.getElementById('emptyState');
const totalCount = document.getElementById('totalCount');
const completedCount = document.getElementById('completedCount');
const authButtons = document.getElementById('authButtons');
const userMenu = document.getElementById('userMenu');
const userName = document.getElementById('userName');
const userEmail = document.getElementById('userEmail');
const userAvatar = document.getElementById('userAvatar');

// ============ AUTH FUNCTIONS ============

function getToken() {
    return localStorage.getItem('token');
}

function setToken(token) {
    localStorage.setItem('token', token);
}

function removeToken() {
    localStorage.removeItem('token');
}

function isLoggedIn() {
    return currentUser !== null;
}

async function checkAuth() {
    const token = getToken();
    if (!token) {
        showLoggedOut();
        return;
    }

    try {
        const response = await fetch('/api/auth/me', {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            currentUser = await response.json();
            showLoggedIn(currentUser);
        } else {
            removeToken();
            showLoggedOut();
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        showLoggedOut();
    }
}

function showLoggedIn(user) {
    authButtons.classList.add('hidden');
    userMenu.classList.remove('hidden');
    userName.textContent = user.name;
    userEmail.textContent = user.email;
    userAvatar.textContent = user.name.charAt(0).toUpperCase();
}

function showLoggedOut() {
    currentUser = null;
    authButtons.classList.remove('hidden');
    userMenu.classList.add('hidden');
}

// ============ LOCAL STORAGE TASKS ============

function getLocalTasks() {
    const stored = localStorage.getItem('localTasks');
    return stored ? JSON.parse(stored) : [];
}

function saveLocalTasks(tasks) {
    localStorage.setItem('localTasks', JSON.stringify(tasks));
}

function addLocalTask(title) {
    const tasks = getLocalTasks();
    const newTask = {
        id: Date.now(),
        title: title,
        completed: false
    };
    tasks.push(newTask);
    saveLocalTasks(tasks);
    return newTask;
}

function toggleLocalTask(id) {
    const tasks = getLocalTasks();
    const task = tasks.find(t => t.id === id);
    if (task) {
        task.completed = !task.completed;
        saveLocalTasks(tasks);
    }
}

function deleteLocalTask(id) {
    let tasks = getLocalTasks();
    tasks = tasks.filter(t => t.id !== id);
    saveLocalTasks(tasks);
}

// ============ MODAL FUNCTIONS ============

function showModal(id) {
    document.getElementById(id).classList.add('active');
}

function hideModal(id) {
    document.getElementById(id).classList.remove('active');
    const error = document.querySelector(`#${id} .form-error`);
    if (error) error.textContent = '';
}

function switchModal(fromId, toId) {
    hideModal(fromId);
    showModal(toId);
}

// ============ AUTH HANDLERS ============

async function handleSignup(e) {
    e.preventDefault();
    const name = document.getElementById('signupName').value;
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;
    const errorEl = document.getElementById('signupError');

    try {
        const response = await fetch('/api/auth/signup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, password })
        });

        const data = await response.json();

        if (response.ok) {
            setToken(data.token);
            currentUser = data.user;
            showLoggedIn(currentUser);
            hideModal('signupModal');
            document.getElementById('signupForm').reset();
            loadTasks();
        } else {
            errorEl.textContent = data.error || 'Signup failed';
        }
    } catch (error) {
        errorEl.textContent = 'Connection error';
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    const errorEl = document.getElementById('loginError');

    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (response.ok) {
            setToken(data.token);
            currentUser = data.user;
            showLoggedIn(currentUser);
            hideModal('loginModal');
            document.getElementById('loginForm').reset();
            loadTasks();
        } else {
            errorEl.textContent = data.error || 'Invalid credentials';
        }
    } catch (error) {
        errorEl.textContent = 'Connection error';
    }
}

function logout() {
    removeToken();
    showLoggedOut();
    loadTasks(); // Will now load from localStorage
}

// ============ TASK FUNCTIONS ============

async function loadTasks() {
    let tasks = [];

    if (isLoggedIn()) {
        // Logged in: get from API
        try {
            const response = await fetch('/api/tasks', {
                headers: { 'Authorization': `Bearer ${getToken()}` }
            });
            tasks = await response.json();
        } catch (error) {
            console.error('Failed to load tasks from API:', error);
            tasks = [];
        }
    } else {
        // Anonymous: get from localStorage
        tasks = getLocalTasks();
    }

    renderTasks(tasks);
}

function renderTasks(tasks) {
    taskList.innerHTML = '';
    
    if (tasks.length === 0) {
        emptyState.classList.add('visible');
    } else {
        emptyState.classList.remove('visible');
        
        let completed = 0;
        tasks.forEach(task => {
            if (task.completed) completed++;
            
            const li = document.createElement('li');
            li.className = `task-item${task.completed ? ' completed' : ''}`;
            li.innerHTML = `
                <input type="checkbox" class="task-checkbox" ${task.completed ? 'checked' : ''} data-id="${task.id}">
                <span class="task-title">${escapeHtml(task.title)}</span>
                <button class="btn-delete" data-id="${task.id}" title="Delete task">🗑️</button>
            `;
            taskList.appendChild(li);
        });

        completedCount.textContent = completed;
    }
    
    totalCount.textContent = tasks.length;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function addTask(title) {
    if (isLoggedIn()) {
        // Logged in: save to API
        try {
            const response = await fetch('/api/tasks', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${getToken()}`
                },
                body: JSON.stringify({ title })
            });

            if (response.ok) {
                loadTasks();
            }
        } catch (error) {
            console.error('Failed to add task:', error);
        }
    } else {
        // Anonymous: save to localStorage
        addLocalTask(title);
        loadTasks();
    }
}

async function toggleTask(id) {
    if (isLoggedIn()) {
        try {
            await fetch(`/api/tasks/${id}`, {
                method: 'PUT',
                headers: { 'Authorization': `Bearer ${getToken()}` }
            });
            loadTasks();
        } catch (error) {
            console.error('Failed to toggle task:', error);
        }
    } else {
        toggleLocalTask(id);
        loadTasks();
    }
}

async function deleteTask(id) {
    if (isLoggedIn()) {
        try {
            await fetch(`/api/tasks/${id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${getToken()}` }
            });
            loadTasks();
        } catch (error) {
            console.error('Failed to delete task:', error);
        }
    } else {
        deleteLocalTask(id);
        loadTasks();
    }
}

// ============ WASM INIT ============

async function initWasm() {
    try {
        const importObject = {
            env: {
                js_log: (ptr, len) => {
                    const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
                    console.log('[WASM]', new TextDecoder().decode(bytes));
                },
                js_renderTasks: () => loadTasks(),
                js_alert: (ptr, len) => {
                    const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
                    alert(new TextDecoder().decode(bytes));
                }
            }
        };

        const response = await fetch('/app.wasm');
        if (!response.ok) throw new Error('WASM fetch failed');
        
        const bytes = await response.arrayBuffer();
        const result = await WebAssembly.instantiate(bytes, importObject);
        
        wasm = result.instance.exports;
        wasmMemory = wasm.memory;
        wasm.init();
        
        console.log('✅ WASM initialized');
    } catch (error) {
        console.log('Running without WASM');
    }
}

// ============ EVENT LISTENERS ============

taskForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const title = taskInput.value.trim();
    if (!title) return;
    
    addTask(title);
    taskInput.value = '';
    taskInput.focus();
});

taskList.addEventListener('click', (e) => {
    const target = e.target;
    const id = parseInt(target.dataset.id) || parseFloat(target.dataset.id);
    
    if (target.classList.contains('task-checkbox')) {
        toggleTask(id);
    } else if (target.classList.contains('btn-delete')) {
        deleteTask(id);
    }
});

// ============ INIT ============

document.addEventListener('DOMContentLoaded', async () => {
    await initWasm();
    await checkAuth();
    loadTasks();
});
