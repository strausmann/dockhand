/**
 * Pure disk-space helper. NO db / docker import, so unit-testable directly
 * (importing docker.ts pulls in Docker-socket detection and the whole
 * Docker-client layer — see host-path-core.ts for the same pattern).
 */
import { statfs } from 'node:fs/promises';

export interface HostDiskInfo {
	diskTotal: number;
	diskFree: number;
	diskAvailable: number;
}

/**
 * Disk space of a filesystem path, via Node's `fs.statfs` (available since
 * Node 18.15). Defaults to measuring `/` when `rootPath` is omitted or an
 * empty string.
 *
 * Callers should pass the Docker daemon's data-root (`DockerRootDir` from
 * Docker's `/info`) instead of relying on the `/` default whenever it's
 * known: on setups where `data-root` in daemon.json points at a separate
 * disk/mount, `/` and the actual data-root can report very different
 * capacity (#976) — measuring `/` alone doesn't tell you whether Docker
 * itself (images, containers, volumes) is about to run out of space.
 *
 * Returns null if the stat fails (e.g. platform without statfs support, or
 * an unreadable/nonexistent path) rather than throwing, since this is a
 * supplementary field on an otherwise-successful response.
 */
export async function getHostDiskInfo(rootPath?: string): Promise<HostDiskInfo | null> {
	const path = rootPath && rootPath.length > 0 ? rootPath : '/';
	try {
		const stats = await statfs(path);
		return {
			diskTotal: stats.blocks * stats.bsize,
			diskFree: stats.bfree * stats.bsize,
			// bavail excludes blocks reserved for the superuser - what's actually
			// usable, and what `df`'s "Avail" column shows.
			diskAvailable: stats.bavail * stats.bsize
		};
	} catch (error) {
		console.warn(`[Host] Failed to read disk stats for "${path}":`, error instanceof Error ? error.message : error);
		return null;
	}
}

/**
 * Disk fields as reported by a hawser-edge agent's periodic metrics message
 * (see `MetricsMessage['metrics']` in hawser.ts and `HawserMetrics` in
 * vite.config.ts) - the agent runs its own statfs()-equivalent against the
 * remote host's Docker data-root and sends the raw numbers over the
 * WebSocket, there is no local getHostDiskInfo() call for this connection
 * type.
 */
export interface EdgeDiskMetrics {
	diskTotal: number;
	diskUsed: number;
	diskFree: number;
}

/**
 * Turns a hawser-edge agent's disk metrics into the same {diskTotal,
 * diskFree, diskAvailable} shape getHostDiskInfo() returns for local
 * connections, so /api/host can treat both connection types uniformly.
 *
 * Returns null when `metrics` is absent (no metrics message has arrived yet)
 * or `diskTotal` is not a positive number. The agent sends 0 for all three
 * disk fields when its own statfs()-equivalent call fails - treating that as
 * "0 bytes free" would render as a false "disk full" alarm in the UI instead
 * of "not available yet", which is what a failed getHostDiskInfo() call
 * already reports as (null) for local connections. Tracking the agent-side
 * 0-vs-null fix itself is out of scope here (see PR description).
 *
 * The agent doesn't send a separate "available" (bavail, excludes blocks
 * reserved for the superuser) figure the way getHostDiskInfo() does locally
 * - only diskTotal/diskUsed/diskFree (see EdgeDiskMetrics above). diskAvailable
 * is therefore derived as diskTotal - diskUsed rather than copied from
 * diskFree, so it stays defined even if a future agent version reports
 * diskFree and diskUsed inconsistently; in practice the two will usually be
 * very close.
 */
export function deriveEdgeDiskInfo(metrics: EdgeDiskMetrics | undefined | null): HostDiskInfo | null {
	if (!metrics || !(metrics.diskTotal > 0)) return null;
	return {
		diskTotal: metrics.diskTotal,
		diskFree: metrics.diskFree,
		diskAvailable: metrics.diskTotal - metrics.diskUsed
	};
}
