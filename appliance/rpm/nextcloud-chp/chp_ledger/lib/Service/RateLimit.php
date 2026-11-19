<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 The CyberHygiene Project
 * SPDX-License-Identifier: Apache-2.0
 */

namespace OCA\ChpLedger\Service;

use OCP\ICacheFactory;
use OCP\IMemcache;

/**
 * At most LIMIT requests per user in any PERIOD seconds (Plan 1 lab record §Ledger: six requests in ten seconds once
 * stopped the appender for the whole site; the appender has its own finite start limits too). Counted with an atomic
 * increment in the server's local memory cache (APCu, shared by the php-fpm workers): one counter per user per
 * minute window, the previous window counted in proportion to how much of it still lies within the last 60 seconds.
 * Every request counts, refused ones too. No atomic counter (no memcache.local) throws: the caller refuses (fail closed).
 */
class RateLimit {
	public const LIMIT = 10;
	public const PERIOD = 60;

	public function __construct(
		private ICacheFactory $cacheFactory,
	) {
	}

	/** True when this request takes $uid over LIMIT requests in the last PERIOD seconds. */
	public function exceeded(string $uid): bool {
		$cache = $this->cacheFactory->createLocal('chp_ledger');
		if (!($cache instanceof IMemcache)) {
			throw new \RuntimeException('no atomic memory cache for the rate limit (memcache.local)');
		}
		$now = time();
		$window = intdiv($now, self::PERIOD);
		$key = 'rl-' . hash('sha256', $uid) . '-';
		$cache->add($key . $window, 0, 3 * self::PERIOD);
		$n = $cache->inc($key . $window);
		if (!is_int($n)) {
			throw new \RuntimeException('the rate-limit counter could not be incremented');
		}
		$prev = $cache->get($key . ($window - 1));
		$share = (self::PERIOD - ($now % self::PERIOD)) / self::PERIOD;
		return $n + (is_int($prev) ? $prev : 0) * $share > self::LIMIT;
	}
}
