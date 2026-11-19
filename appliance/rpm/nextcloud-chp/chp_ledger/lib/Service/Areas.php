<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 The CyberHygiene Project
 * SPDX-License-Identifier: Apache-2.0
 */

namespace OCA\ChpLedger\Service;

use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IAppConfig;
use OCP\IDBConnection;

/**
 * Which controlled-document area holds a file id. The site's areas are read from app config on every call
 * (chp-site documents enable renders them from /etc/chp/documents.conf; nothing here is a constant):
 *   compliance  JSON list [<folder file id>, ...]  CUI_COMPLIANCE_ID, INTERNAL_COMPLIANCE_ID
 *   superseded  JSON list [<folder file id>, ...]  CUI_SUPERSEDED_ID, INTERNAL_SUPERSEDED_ID
 * A file id is allowed when the area folder itself or one of its ancestors is a compliance id, and none of them is
 * a superseded id (Internal/Compliance/Superseded sits inside Internal/Compliance). Ancestry is read from the
 * filecache by parent, on the storage itself: never from the path the user sees (a team folder mount is a jail of
 * its storage, so a path_hash of that path names another row; chp_foldertag, Plan 2) and never from a folder the user
 * named "Compliance". A missing or malformed key, or a walk that cannot finish, throws: the caller refuses.
 */
class Areas {
	public const APP_ID = 'chp_ledger';
	private const MAX_DEPTH = 64;

	public function __construct(
		private IAppConfig $config,
		private IDBConnection $db,
	) {
	}

	/** The compliance area id that holds $fileId, or null when it is outside every one or inside a Superseded area. */
	public function areaOf(int $fileId): ?int {
		$allowed = $this->ids('compliance');
		$superseded = $this->ids('superseded');
		$found = null;
		$seen = [];
		$storage = null;
		$id = $fileId;
		for ($depth = 0; $id > 0; $depth++) {
			if ($depth > self::MAX_DEPTH || isset($seen[$id])) {
				throw new \RuntimeException('filecache ancestry of file id ' . $fileId . ' does not end (cycle or depth)');
			}
			$seen[$id] = true;
			if (in_array($id, $superseded, true)) {
				return null;
			}
			if ($found === null && in_array($id, $allowed, true)) {
				$found = $id;
			}
			$row = $this->row($id);
			if ($row === null) {
				throw new \RuntimeException('file id ' . $id . ' is not in the filecache');
			}
			if ($storage !== null && (int)$row['storage'] !== $storage) {
				throw new \RuntimeException('filecache ancestry of file id ' . $fileId . ' changes storage');
			}
			$storage = (int)$row['storage'];
			$id = (int)$row['parent'];
		}
		return $found;
	}

	/** @return array{storage:int|string,parent:int|string}|null */
	private function row(int $id): ?array {
		$q = $this->db->getQueryBuilder();
		$q->select('storage', 'parent')->from('filecache')
			->where($q->expr()->eq('fileid', $q->createNamedParameter($id, IQueryBuilder::PARAM_INT)));
		$r = $q->executeQuery();
		$row = $r->fetch();
		$r->closeCursor();
		return is_array($row) ? $row : null;
	}

	/** @return list<int> */
	private function ids(string $key): array {
		$raw = $this->config->getValueString(self::APP_ID, $key, '');
		$v = json_decode($raw, true);
		if (!is_array($v) || !array_is_list($v) || $v === []) {
			throw new \RuntimeException('app config chp_ledger/' . $key . ' is missing or not a JSON list of file ids');
		}
		foreach ($v as $id) {
			if (!is_int($id) || $id <= 0) {
				throw new \RuntimeException('app config chp_ledger/' . $key . ' has a value that is not a file id');
			}
		}
		return $v;
	}
}
