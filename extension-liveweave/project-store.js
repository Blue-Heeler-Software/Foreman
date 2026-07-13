const DB_NAME = 'foreman-liveweave';
const DB_VERSION = 1;
const PROJECTS = 'projects';
const META = 'meta';
const HANDLES = 'handles';

let dbPromise = null;

function requestResult(request) {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error('IndexedDB request failed.'));
    });
}

function openDb() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onupgradeneeded = () => {
            const db = request.result;
            if (!db.objectStoreNames.contains(PROJECTS)) {
                const store = db.createObjectStore(PROJECTS, { keyPath: 'id' });
                store.createIndex('updatedAt', 'updatedAt');
            }
            if (!db.objectStoreNames.contains(META)) db.createObjectStore(META, { keyPath: 'key' });
            if (!db.objectStoreNames.contains(HANDLES)) db.createObjectStore(HANDLES, { keyPath: 'projectId' });
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error('Could not open LiveWeave project storage.'));
    });
    return dbPromise;
}

async function store(name, mode = 'readonly') {
    const db = await openDb();
    return db.transaction(name, mode).objectStore(name);
}

export async function putProject(project) {
    const s = await store(PROJECTS, 'readwrite');
    await requestResult(s.put(project));
    return project;
}

export async function getProject(id) {
    if (!id) return null;
    return (await requestResult((await store(PROJECTS)).get(id))) || null;
}

export async function listProjects(limit = 12) {
    const all = await requestResult((await store(PROJECTS)).getAll());
    return all.sort((a, b) => String(b.updatedAt || '').localeCompare(String(a.updatedAt || ''))).slice(0, limit);
}

export async function setActiveProjectId(projectId) {
    await requestResult((await store(META, 'readwrite')).put({ key: 'activeProjectId', value: projectId || '' }));
}

export async function getActiveProjectId() {
    const item = await requestResult((await store(META)).get('activeProjectId'));
    return item?.value || '';
}

export async function getActiveProject() {
    return getProject(await getActiveProjectId());
}

export async function putProjectHandle(projectId, handle) {
    if (!projectId || !handle) return;
    await requestResult((await store(HANDLES, 'readwrite')).put({ projectId, handle }));
}

export async function getProjectHandle(projectId) {
    if (!projectId) return null;
    const item = await requestResult((await store(HANDLES)).get(projectId));
    return item?.handle || null;
}
