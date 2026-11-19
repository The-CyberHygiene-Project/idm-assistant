<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 The CyberHygiene Project
 * SPDX-License-Identifier: Apache-2.0
 */

namespace OCA\ChpLedger\Service;

/**
 * The two directories shared with the root appender (nextcloud-chp makes both):
 *   spool  root:apache 1730, httpd_sys_rw_content_t: the app creates <id>.json; it cannot list the directory or touch
 *          another file (sticky); only root reads them
 *   out    root:apache 0750, httpd_sys_content_t: the appender's results <id>.json; read-only to the web server
 */
class Spool {
	public const SPOOL = '/var/lib/chp-docs/spool';
	public const OUT = '/var/lib/chp-docs/out';
	private const MAX_RESULT = 1048576;

	/**
	 * Writes $doc as SPOOL/<id>.json. It is first written to .<id>.tmp, created with O_CREAT|O_EXCL (fopen 'x': an
	 * existing name, a symlink included, is never followed or reused) and mode 0640 (umask), written and fsynced;
	 * then hard-linked to <id>.json, which fails when that name exists (never an overwrite), and the temporary
	 * name removed. So the appender (it reads <id>.json names only) never sees a half-written request.
	 * Returns false when <id>.json already exists; throws on any other failure.
	 */
	public function write(string $id, array $doc): bool {
		$json = json_encode($doc, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
		$tmp = self::SPOOL . '/.' . $id . '.tmp';
		$final = self::SPOOL . '/' . $id . '.json';
		$old = umask(0137);
		try {
			$fh = @fopen($tmp, 'xb');
		} finally {
			umask($old);
		}
		if ($fh === false) {
			throw new \RuntimeException('cannot create the spool file');
		}
		try {
			try {
				$ok = fwrite($fh, $json) === strlen($json) && fflush($fh) && fsync($fh);
			} finally {
				fclose($fh);
				unset($json);
			}
			if (!$ok) {
				throw new \RuntimeException('cannot write the spool file');
			}
			if (@link($tmp, $final)) {
				return true;
			}
			clearstatcache(true, $final);
			if (file_exists($final) || is_link($final)) {
				return false;
			}
			throw new \RuntimeException('cannot link the spool file');
		} finally {
			@unlink($tmp);
		}
	}

	/** Whether <id>.json is still waiting in the spool (a lookup by name: the directory is not listable). */
	public function queued(string $id): bool {
		return file_exists(self::SPOOL . '/' . $id . '.json');
	}

	/**
	 * The appender's result for $id, or null when it has written none. A result that is not a regular file, is
	 * too large or is not a JSON object throws (the caller refuses).
	 */
	public function result(string $id): ?array {
		$f = self::OUT . '/' . $id . '.json';
		clearstatcache(true, $f);
		if (is_link($f)) {
			throw new \RuntimeException('the result is a symlink');
		}
		if (!file_exists($f)) {
			return null;
		}
		if (!is_file($f)) {
			throw new \RuntimeException('the result is not a regular file');
		}
		$raw = file_get_contents($f, false, null, 0, self::MAX_RESULT + 1);
		if ($raw === false || strlen($raw) > self::MAX_RESULT) {
			throw new \RuntimeException('the result cannot be read or is too large');
		}
		$r = json_decode($raw, true);
		if (!is_array($r) || array_is_list($r)) {
			throw new \RuntimeException('the result is not a JSON object');
		}
		return $r;
	}
}
