<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 The CyberHygiene Project
 * SPDX-License-Identifier: Apache-2.0
 */

namespace OCA\ChpFolderTag\Service;

use OCP\Files\Mount\IMountManager;
use OCP\Files\Mount\IMountPoint;
use OCP\IAppConfig;

/**
 * The site's policy, read from app config on every call (chp-site sets it; nothing here is a constant):
 *   rules          JSON object {"<team folder id>": "<system tag id>", ...}   tag by folder
 *   contain        JSON list   [<team folder id>, ...]                       copy/move out refused
 *   contain_allow  JSON list   [[<from id>, <to id>], ...]                   exceptions to "contain"
 * A key that is missing or empty means "nothing configured". A key that is present but not valid JSON of the
 * right shape raises PolicyError, and every caller fails closed on it.
 */
class Policy {
	public const APP_ID = 'chp_foldertag';

	public function __construct(
		private IAppConfig $config,
		private IMountManager $mounts,
	) {
	}

	/** @return array<int,string> team folder id => system tag id */
	public function rules(): array {
		$raw = $this->config->getValueString(self::APP_ID, 'rules', '');
		if (trim($raw) === '') {
			return [];
		}
		$r = json_decode($raw, true);
		if (!is_array($r) || ($r !== [] && array_is_list($r))) {
			throw new PolicyError('app config chp_foldertag/rules is not a JSON object');
		}
		$out = [];
		foreach ($r as $fid => $tag) {
			if (!self::isId($fid) || !self::isId($tag)) {
				throw new PolicyError('app config chp_foldertag/rules has a non-numeric folder or tag id');
			}
			$out[(int)$fid] = (string)$tag;
		}
		return $out;
	}

	/** @return list<string> every system tag id named by a rule */
	public function managedTags(): array {
		return array_values(array_unique(array_values($this->rules())));
	}

	/** @return list<int> */
	public function contained(): array {
		$raw = $this->config->getValueString(self::APP_ID, 'contain', '');
		if (trim($raw) === '') {
			return [];
		}
		$c = json_decode($raw, true);
		if (!is_array($c) || !array_is_list($c)) {
			throw new PolicyError('app config chp_foldertag/contain is not a JSON list');
		}
		foreach ($c as $fid) {
			if (!self::isId($fid)) {
				throw new PolicyError('app config chp_foldertag/contain has a non-numeric folder id');
			}
		}
		return array_map('intval', $c);
	}

	/** @return list<array{0:int,1:int}> */
	public function allowedPairs(): array {
		$raw = $this->config->getValueString(self::APP_ID, 'contain_allow', '');
		if (trim($raw) === '') {
			return [];
		}
		$a = json_decode($raw, true);
		if (!is_array($a) || !array_is_list($a)) {
			throw new PolicyError('app config chp_foldertag/contain_allow is not a JSON list');
		}
		$out = [];
		foreach ($a as $pair) {
			if (!is_array($pair) || !array_is_list($pair) || count($pair) !== 2 || !self::isId($pair[0]) || !self::isId($pair[1])) {
				throw new PolicyError('app config chp_foldertag/contain_allow entries must be [from id, to id]');
			}
			$out[] = [(int)$pair[0], (int)$pair[1]];
		}
		return $out;
	}

	/**
	 * Is a copy or move from team folder $src to $dst (null = not a team folder, e.g. a home folder) refused?
	 * Refused when the source is contained, the target is a different place, and the pair is not an exception.
	 */
	public function refuses(?int $src, ?int $dst): bool {
		if ($src === null || !in_array($src, $this->contained(), true)) {
			return false;
		}
		if ($dst === $src) {
			return false;
		}
		if ($dst === null) {
			return true;
		}
		return !in_array([$src, $dst], $this->allowedPairs(), true);
	}

	/** The team folder id of a mount point, or null when it is not a team folder. */
	public static function folderOfMount(?IMountPoint $mp): ?int {
		if ($mp === null || !method_exists($mp, 'getFolderId')) {
			return null;
		}
		return (int)$mp->getFolderId();
	}

	/** The team folder id that holds an absolute NextCloud path (/<user>/files/...), or null. */
	public function folderOfPath(string $path): ?int {
		return self::folderOfMount($this->mounts->find($path));
	}

	private static function isId(mixed $v): bool {
		return (is_int($v) && $v > 0) || (is_string($v) && preg_match('/^[1-9][0-9]*$/', $v) === 1);
	}
}
