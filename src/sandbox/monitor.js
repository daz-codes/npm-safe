export function parseStraceLog(raw) {
  const lines = raw.split('\n').filter(Boolean);

  const network = [];
  const fileWrites = [];
  const processes = [];

  for (const line of lines) {
    const net = parseNetworkCall(line);
    if (net) { network.push(net); continue; }

    const fw = parseFileWrite(line);
    if (fw) { fileWrites.push(fw); continue; }

    const proc = parseProcessSpawn(line);
    if (proc) processes.push(proc);
  }

  return {
    network: dedup(network, (n) => `${n.address}:${n.port}`),
    fileWrites: dedup(fileWrites, (f) => f.path),
    processes: dedup(processes, (p) => p.command),
  };
}

// connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16)
// connect(3, {sa_family=AF_INET6, sin6_port=htons(80), sin6_addr=inet6_addr("::1")}, 28)
const CONNECT_RE = /connect\(\d+,\s*\{sa_family=AF_INET6?,.*?(?:sin6?_port=htons\((\d+)\)).*?(?:inet6?_addr\("([^"]+)"\))/;

// sendto(3, ..., {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, ...)
const SENDTO_RE = /sendto\(\d+,.*?\{sa_family=AF_INET6?,.*?(?:sin6?_port=htons\((\d+)\)).*?(?:inet6?_addr\("([^"]+)"\))/;

// socket(AF_INET, SOCK_STREAM, ...) = 3
const SOCKET_RE = /socket\(AF_INET6?,\s*SOCK_STREAM/;

function parseNetworkCall(line) {
  let m = line.match(CONNECT_RE);
  if (m) return { syscall: 'connect', port: parseInt(m[1], 10), address: m[2] };

  m = line.match(SENDTO_RE);
  if (m) return { syscall: 'sendto', port: parseInt(m[1], 10), address: m[2] };

  // socket() alone just means a socket was created — less interesting without connect
  // but worth tracking for completeness
  if (SOCKET_RE.test(line) && !line.includes('= -1')) {
    return { syscall: 'socket', port: null, address: null };
  }

  return null;
}

// openat(AT_FDCWD, "/etc/passwd", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3
// openat(AT_FDCWD, "/some/path", O_RDWR|O_CREAT, 0666) = 5
// Must have O_WRONLY or O_RDWR — O_CREAT alone with O_RDONLY is not a write
// Also match truncated strace output where the path ends with "...
// Match both normal: "path" and truncated: "path"... output
const OPENAT_WRITE_RE = /openat\(.*?"([^"]*)"?\.{0,3}\s*,?\s*.*?O_(?:WRONLY|RDWR)/;

// rename("/tmp/evil", "/sandbox/node_modules/.bin/node") = 0
// renameat(AT_FDCWD, "/tmp/evil", AT_FDCWD, "/sandbox/.bin/node") = 0
// renameat2(AT_FDCWD, "/tmp/evil", AT_FDCWD, "/target", ...) = 0
// rename("src", "dest") — capture the destination (last quoted path before ) = 0)
// renameat(AT_FDCWD, "src", AT_FDCWD, "dest") = 0
// renameat2(AT_FDCWD, "src", AT_FDCWD, "dest", ...) = 0
const RENAME_TARGET_RE = /rename(?:at2?)?\(.*,\s*(?:AT_FDCWD,\s*)?"([^"]*)"/;

// symlink("target_path", "link_path") — flag the link_path (second arg)
const SYMLINK_RE = /symlink\("[^"]*",\s*"([^"]*)"/;

// link("existing", "new_link") / linkat(AT_FDCWD, "existing", AT_FDCWD, "new_link", ...)
const LINK_TARGET_RE = /link(?:at)?\(.*,\s*(?:AT_FDCWD,\s*)?"([^"]*)"/;

function parseFileWrite(line) {
  // openat with write flags
  let m = line.match(OPENAT_WRITE_RE);
  if (m) {
    const path = cleanStracePath(m[1]);
    if (path && !isNoisePath(path)) return { path, syscall: 'openat' };
  }

  // rename/renameat/renameat2 — flag the target (destination) path
  m = line.match(RENAME_TARGET_RE);
  if (m && line.match(/=\s*0/)) {
    const path = cleanStracePath(m[1]);
    if (path && !isNoisePath(path)) return { path, syscall: 'rename' };
  }

  // symlink — flag the target (second arg)
  m = line.match(SYMLINK_RE);
  if (m && line.match(/=\s*0/)) {
    const path = cleanStracePath(m[1]);
    if (path && !isNoisePath(path)) return { path, syscall: 'symlink' };
  }

  // link/linkat — flag the target path
  m = line.match(LINK_TARGET_RE);
  if (m && line.match(/=\s*0/)) {
    const path = cleanStracePath(m[1]);
    if (path && !isNoisePath(path)) return { path, syscall: 'link' };
  }

  return null;
}

function cleanStracePath(raw) {
  // Remove trailing quote if present, handle truncated output ("path...")
  return raw.replace(/"+$/, '').replace(/\.\.\.+$/, '');
}

function isNoisePath(path) {
  return path.startsWith('/dev/') || path.startsWith('/proc/') || path === '/tmp/strace.log';
}

// execve("/usr/bin/node", ["node", "install.js"], ...) = 0
// execve("/bin/sh", ["sh", "-c", "echo pwned"], ...) = 0
const EXECVE_RE = /execve\("([^"]+)",\s*\[([^\]]*)\]/;

function parseProcessSpawn(line) {
  const m = line.match(EXECVE_RE);
  if (!m) return null;

  const executable = m[1];
  const command = executable.split('/').pop();
  const argsRaw = m[2];

  return { executable, command, args: argsRaw };
}

function dedup(arr, keyFn) {
  const seen = new Set();
  return arr.filter((item) => {
    const key = keyFn(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
