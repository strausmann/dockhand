import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getHostDiskInfo, deriveEdgeDiskInfo } from '../src/lib/server/host-disk-core';

describe('getHostDiskInfo', () => {
	it('defaults to "/" when called without a path', async () => {
		const result = await getHostDiskInfo();

		assert.ok(result !== null);
		assert.ok(result!.diskTotal > 0);
		assert.ok(result!.diskFree >= 0);
		assert.ok(result!.diskAvailable >= 0);
	});

	it('defaults to "/" when passed an empty string', async () => {
		const result = await getHostDiskInfo('');

		assert.ok(result !== null);
	});

	it('measures the given path, not a hardcoded "/"', async () => {
		// A directory that definitely exists but is not '/' itself - proves the
		// argument actually reaches statfs() instead of being ignored.
		const dir = mkdtempSync(join(tmpdir(), 'dockhand-host-disk-test-'));
		try {
			const result = await getHostDiskInfo(dir);
			assert.ok(result !== null);
			assert.ok(result!.diskTotal > 0);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it('returns null for a path that does not exist, instead of silently falling back to "/"', async () => {
		const bogusPath = '/this/path/almost-certainly/does-not-exist-dockhand-1397';

		const result = await getHostDiskInfo(bogusPath);

		assert.equal(result, null);
	});
});

describe('deriveEdgeDiskInfo', () => {
	it('maps non-zero agent metrics to the {diskTotal, diskFree, diskAvailable} shape', () => {
		const result = deriveEdgeDiskInfo({ diskTotal: 1000, diskUsed: 400, diskFree: 600 });

		assert.deepEqual(result, {
			diskTotal: 1000,
			diskFree: 600,
			// Agent has no separate "available" field - derived as total - used,
			// not copied from diskFree (see doc comment on deriveEdgeDiskInfo()).
			diskAvailable: 600
		});
	});

	it('derives diskAvailable as diskTotal - diskUsed, not as a copy of diskFree', () => {
		// diskFree deliberately disagrees with diskTotal - diskUsed, so a test
		// that only checked equality with diskFree could not tell the two
		// implementations apart.
		const result = deriveEdgeDiskInfo({ diskTotal: 1000, diskUsed: 250, diskFree: 600 });

		assert.equal(result?.diskAvailable, 750);
		assert.equal(result?.diskFree, 600);
	});

	it('treats diskTotal of 0 as "not available" (null), not as "0 bytes free"', () => {
		// The agent sends all-zero disk fields when its own statfs()-equivalent
		// call fails - a literal 0 must not render as a false "disk full" alarm.
		const result = deriveEdgeDiskInfo({ diskTotal: 0, diskUsed: 0, diskFree: 0 });

		assert.equal(result, null);
	});

	it('treats a negative diskTotal as "not available" (null)', () => {
		const result = deriveEdgeDiskInfo({ diskTotal: -1, diskUsed: 0, diskFree: 0 });

		assert.equal(result, null);
	});

	it('returns null when no metrics have arrived yet (undefined)', () => {
		const result = deriveEdgeDiskInfo(undefined);

		assert.equal(result, null);
	});

	it('returns null for an explicit null (same "no metrics yet" case)', () => {
		const result = deriveEdgeDiskInfo(null);

		assert.equal(result, null);
	});
});
