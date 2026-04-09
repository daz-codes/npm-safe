import Docker from 'dockerode';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { unlink, mkdir, readdir, rm, readFile as readFileBuf } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
const IMAGE_NAME = 'npm-safe-sandbox';
const DOCKERFILE_DIR = join(__dirname, '..', '..', 'sandbox');

export function createDockerClient(config = {}) {
  const docker = new Docker();
  const timeout = (config.sandbox?.timeout || 60) * 1000;
  const memoryLimit = parseMemoryLimit(config.sandbox?.memoryLimit || '256m');
  const cpuLimit = parseFloat(config.sandbox?.cpuLimit || '0.5');

  return { ensureImage, runSandbox };

  async function ensureImage() {
    try {
      await docker.getImage(IMAGE_NAME).inspect();
    } catch {
      const stream = await docker.buildImage(
        { context: DOCKERFILE_DIR, src: ['Dockerfile'] },
        { t: IMAGE_NAME }
      );
      await new Promise((resolve, reject) => {
        docker.modem.followProgress(stream, (err) => (err ? reject(err) : resolve()));
      });
    }
  }

  async function runSandbox(packageName, packageVersion) {
    await ensureImage();

    // 1. Download tarball on the host via npm pack
    const tarballPath = await packPackage(packageName, packageVersion);

    const container = await docker.createContainer({
      Image: IMAGE_NAME,
      Cmd: [
        'strace', '-f', '-s', '4096', '-e', 'trace=network,process,file',
        '-o', '/tmp/strace.log',
        '--',
        'npm', 'install', '/sandbox/package.tgz',
      ],
      WorkingDir: '/sandbox',
      NetworkDisabled: true,
      HostConfig: {
        NetworkMode: 'none',
        Memory: memoryLimit,
        NanoCpus: cpuLimit * 1e9,
        ReadonlyRootfs: true,
        CapAdd: ['SYS_PTRACE'],
        Tmpfs: {
          '/tmp': 'rw,noexec,nosuid,size=64m',
          '/home/sandboxuser/.npm': 'rw,noexec,nosuid,size=128m',
        },
      },
      User: 'sandboxuser',
    });

    try {
      // 2. Copy tarball into container before starting
      await putFileInContainer(container, tarballPath, '/sandbox/package.tgz');

      // 3. Start and wait with timeout
      await container.start();

      const result = await waitWithTimeout(container, timeout);

      // 4. Collect strace output from stopped container via archive API
      const straceLog = await getFileFromContainer(container, '/tmp/strace.log');

      // 5. Collect installed file listing via exec on the stopped container's filesystem
      //    Use docker cp + archive API instead of restarting (which would re-run install scripts)
      const fileList = await getFileListFromContainer(container);

      return {
        exitCode: result.StatusCode,
        straceLog,
        fileList,
        packageName,
        packageVersion,
      };
    } finally {
      try { await container.stop().catch(() => {}); } catch { /* already stopped */ }
      try { await container.remove(); } catch { /* already removed */ }
      try { await rm(dirname(tarballPath), { recursive: true, force: true }); } catch { /* best effort cleanup */ }
    }
  }
}

async function packPackage(name, version) {
  // Use a unique temp directory per call to avoid race conditions with concurrent runs
  const tmpDir = join(tmpdir(), `safe-install-pack-${randomBytes(8).toString('hex')}`);
  await mkdir(tmpDir, { recursive: true });

  try {
    await exec(
      'npm', ['pack', `${name}@${version}`, '--pack-destination', tmpDir],
      { cwd: tmpDir }
    );

    const files = (await readdir(tmpDir)).filter((f) => f.endsWith('.tgz'));

    if (files.length === 0) {
      throw new Error(`npm pack did not produce a tarball for ${name}@${version}`);
    }

    return join(tmpDir, files[0]);
  } catch (err) {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    throw err;
  }
}

async function putFileInContainer(container, hostPath, containerPath) {
  const content = await readFileBuf(hostPath);
  const targetName = containerPath.split('/').pop();

  // Build a minimal POSIX tar archive in memory (one file, no compression)
  const tarBuf = buildTarBuffer(targetName, content);
  await container.putArchive(tarBuf, { path: dirname(containerPath) });
}

function buildTarBuffer(filename, content) {
  // POSIX tar: 512-byte header + content padded to 512-byte blocks + 1024 zero bytes
  const header = Buffer.alloc(512, 0);

  // name (0-99)
  header.write(filename, 0, Math.min(filename.length, 100), 'utf8');
  // mode (100-107)
  header.write('0000644\0', 100, 8, 'utf8');
  // uid (108-115) — 1000 decimal = 1750 octal (sandboxuser)
  header.write('0001750\0', 108, 8, 'utf8');
  // gid (116-123) — 1000 decimal = 1750 octal (sandboxuser)
  header.write('0001750\0', 116, 8, 'utf8');
  // size in octal (124-135)
  header.write(content.length.toString(8).padStart(11, '0') + '\0', 124, 12, 'utf8');
  // mtime (136-147)
  header.write(Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + '\0', 136, 12, 'utf8');
  // typeflag (156) — '0' = regular file
  header.write('0', 156, 1, 'utf8');

  // Compute checksum: sum of all bytes with checksum field (148-155) treated as spaces
  header.fill(' ', 148, 156);
  let checksum = 0;
  for (let i = 0; i < 512; i++) checksum += header[i];
  header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'utf8');

  // Content padded to 512-byte boundary
  const padding = 512 - (content.length % 512 || 512);
  const body = padding > 0 && padding < 512
    ? Buffer.concat([content, Buffer.alloc(padding, 0)])
    : content;

  // End-of-archive marker: two 512-byte zero blocks
  return Buffer.concat([header, body, Buffer.alloc(1024, 0)]);
}

async function waitWithTimeout(container, timeout) {
  let timer;
  try {
    return await Promise.race([
      container.wait(),
      new Promise((_, reject) => {
        timer = setTimeout(async () => {
          try { await container.stop({ t: 0 }); } catch { /* ignore */ }
          reject(new Error(`Sandbox timed out after ${timeout / 1000}s`));
        }, timeout);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function getFileFromContainer(container, filePath) {
  const stream = await container.getArchive({ path: filePath });
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  const archive = Buffer.concat(chunks);

  // Tar archive: 512-byte header, then file content.
  // File size is in header bytes 124-135 (octal, null-terminated).
  const sizeStr = archive.subarray(124, 135).toString('utf8').replace(/\0/g, '').trim();
  const size = parseInt(sizeStr, 8);
  return archive.subarray(512, 512 + size).toString('utf8');
}

async function getFileListFromContainer(container) {
  // Extract /sandbox/node_modules as a tar archive and parse filenames from tar headers.
  // This avoids restarting the container (which would re-run install scripts).
  let stream;
  try {
    stream = await container.getArchive({ path: '/sandbox/node_modules' });
  } catch {
    return ''; // node_modules doesn't exist — no files installed
  }

  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  const archive = Buffer.concat(chunks);

  const files = [];
  let offset = 0;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    // End-of-archive: two consecutive zero blocks
    if (header.every((b) => b === 0)) break;

    const name = header.subarray(0, 100).toString('utf8').replace(/\0/g, '');
    const sizeStr = header.subarray(124, 135).toString('utf8').replace(/\0/g, '').trim();
    const size = parseInt(sizeStr, 8) || 0;
    const typeflag = String.fromCharCode(header[156]);

    // '0' or '\0' = regular file
    if (typeflag === '0' || typeflag === '\0') {
      files.push(`/sandbox/node_modules/${name}`);
    }

    // Advance past header + content (padded to 512-byte boundary)
    offset += 512 + Math.ceil(size / 512) * 512;
  }

  return files.join('\n');
}

async function execInContainer(docker, container, cmd) {
  const ex = await container.exec({
    Cmd: cmd,
    AttachStdout: true,
    AttachStderr: true,
    User: 'root',
  });

  const stream = await ex.start({ Detach: false });

  return new Promise((resolve, reject) => {
    const stdout = [];
    const stderr = [];

    docker.modem.demuxStream(stream, {
      write: (chunk) => stdout.push(chunk),
    }, {
      write: (chunk) => stderr.push(chunk),
    });

    stream.on('end', () => resolve(Buffer.concat(stdout).toString('utf8')));
    stream.on('error', reject);
  });
}

function parseMemoryLimit(str) {
  const match = str.match(/^(\d+)(m|g)$/i);
  if (!match) return 256 * 1024 * 1024;
  const val = parseInt(match[1], 10);
  return match[2].toLowerCase() === 'g' ? val * 1024 * 1024 * 1024 : val * 1024 * 1024;
}
