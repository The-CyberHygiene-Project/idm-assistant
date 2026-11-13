<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 The CyberHygiene Project
 * SPDX-License-Identifier: Apache-2.0
 */

namespace OCA\ChpFolderTag\Listener;

use OCA\ChpFolderTag\Service\Audit;
use OCA\ChpFolderTag\Service\Policy;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\Exceptions\AbortedEventException;
use OCP\Files\Events\Node\BeforeNodeDeletedEvent;
use OCP\Files\Events\Node\BeforeNodeRenamedEvent;
use OCP\Files\File;
use OCP\Files\Folder;
use OCP\Files\Node;
use OCP\ICacheFactory;
use OCP\IDBConnection;

/**
 * Stopgap for a NextCloud defect under FIPS: moving, renaming or deleting (= moving to the trash) a folder that
 * has children updates the children's path_hash with the database's MD5(), and PostgreSQL in FIPS mode refuses
 * MD5 ("could not compute MD5 hash: unsupported"). The files are already moved on disk when that query fails, so
 * the request ends in a 500 with the database and the disk out of step, and the moved files reappear later as NEW,
 * UNTAGGED entries. While the database refuses MD5, this listener refuses such operations before anything moves
 * (chp.folderop.refused; WebDAV answers 403, or 500 "Failed to rename" for a rename in the same parent, with
 * nothing changed). The same happens to a FILE moved from a team folder to another place when it has old
 * versions: groupfolders then moves the file's versions folder. It checks the database at most every 10 minutes
 * and stops refusing by itself once MD5 works (the fix belongs in the database set-up). Empty folders, files
 * without old versions, and moves inside one team folder are not affected.
 *
 * @template-implements IEventListener<Event>
 */
class FolderGuardListener implements IEventListener {
	public function __construct(
		private IDBConnection $db,
		private ICacheFactory $cacheFactory,
		private Audit $audit,
		private Policy $policy,
	) {
	}

	public function handle(Event $event): void {
		if ($event instanceof BeforeNodeRenamedEvent) {
			[$node, $op, $target] = [$event->getSource(), 'move', $event->getTarget()->getPath()];
		} elseif ($event instanceof BeforeNodeDeletedEvent) {
			[$node, $op, $target] = [$event->getNode(), 'delete', null];
		} else {
			return;
		}
		// NextCloud's hook layer swallows any exception except AbortedEventException and lets the operation go on;
		// on any other error refuse folders and files leaving their team folder (fail closed), let the rest pass.
		try {
			$this->decide($node, $op, $target);
		} catch (AbortedEventException $e) {
			throw $e;
		} catch (\Throwable $e) {
			if (!($node instanceof Folder || ($node instanceof File && $target !== null && $this->leavesOrUnknown($node, $target)))) {
				return;
			}
			$path = '';
			try {
				$path = $node->getPath();
			} catch (\Throwable $ignored) {
				$path = 'unknown';
			}
			$reason = 'internal error: ' . get_class($e);
			try {   // the refusal below must happen even when the audit write fails
				$this->audit->event(Audit::FOLDEROP_REFUSED, 'refused ' . $op . ' (' . $reason . ': ' . $e->getMessage() . '): ' . $path
					. ($target !== null ? ' -> ' . $target : ''),
					['op' => $op, 'source' => $path, 'target' => $target, 'reason' => $reason]);
			} catch (\Throwable $ignored) {
			}
			throw new AbortedEventException('chp_foldertag: ' . $op . ' refused (internal error)');
		}
	}

	private function decide(Node $node, string $op, ?string $target): void {
		if ($node instanceof Folder && $this->hasChildren($node)) {
			$what = 'a non-empty folder';
		} elseif ($node instanceof File && $target !== null && $this->leavesTeamFolder($node, $target) && $this->hasOldVersions($node)) {
			$what = 'a file with old versions to another folder';
		} else {
			return;
		}
		if ($this->md5Works()) {
			return;
		}
		$reason = 'the database refuses MD5 (FIPS), so NextCloud cannot move ' . $what;
		$this->audit->event(Audit::FOLDEROP_REFUSED, 'refused ' . $op . ' of ' . $what . ': ' . $reason . ': ' . $node->getPath()
			. ($target !== null ? ' -> ' . $target : ''),
			['op' => $op, 'source' => $node->getPath(), 'target' => $target, 'reason' => $reason]);
		throw new AbortedEventException('chp_foldertag: ' . $what . ' cannot be moved or deleted on this server yet (database MD5 unavailable)');
	}

	private function leavesOrUnknown(File $file, string $target): bool {
		try {
			return $this->leavesTeamFolder($file, $target);
		} catch (\Throwable $e) {
			return true;
		}
	}

	private function leavesTeamFolder(Node $node, string $target): bool {
		$src = Policy::folderOfMount($node->getMountPoint());
		return $src !== null && $this->policy->folderOfPath($target) !== $src;
	}

	/**
	 * Whether the folder has any child, counted in the filecache by parent. Not the acting user's directory
	 * listing: groupfolders ACLs hide children from it (an ACL-hidden child would make the folder look empty and
	 * its move would hit the MD5 failure).
	 */
	private function hasChildren(Folder $folder): bool {
		try {
			$id = (int)$folder->getId();
			if ($id <= 0) {
				return true;   // not in the filecache yet: cannot tell (fail closed)
			}
			$q = $this->db->getQueryBuilder();
			$q->select($q->func()->count('fileid'))->from('filecache')
				->where($q->expr()->eq('parent', $q->createNamedParameter($id, IQueryBuilder::PARAM_INT)));
			$r = $q->executeQuery();
			$n = (int)$r->fetchOne();
			$r->closeCursor();
			return $n > 0;
		} catch (\Throwable $e) {
			return true;   // cannot tell: treat as non-empty (fail closed)
		}
	}

	/** groupfolders keeps a team folder file's old versions in versions/<file id> of the folder's own storage. */
	private function hasOldVersions(File $file): bool {
		try {
			$storage = $file->getStorage()->getCache()->getNumericStorageId();
			$q = $this->db->getQueryBuilder();
			$q->select($q->func()->count('c.fileid'))->from('filecache', 'p')
				->innerJoin('p', 'filecache', 'c', $q->expr()->eq('c.parent', 'p.fileid'))
				->where($q->expr()->eq('p.storage', $q->createNamedParameter($storage)))
				->andWhere($q->expr()->eq('p.path_hash', $q->createNamedParameter(md5('versions/' . $file->getId()))));
			$r = $q->executeQuery();
			$n = (int)$r->fetchOne();
			$r->closeCursor();
			return $n > 0;
		} catch (\Throwable $e) {
			return true;   // cannot tell: treat as having versions (fail closed)
		}
	}

	private function md5Works(): bool {
		$cache = $this->cacheFactory->createLocal('chp_foldertag');
		$known = $cache->get('db_md5');
		if ($known === 'yes' || $known === 'no') {
			return $known === 'yes';
		}
		if ($this->db->inTransaction()) {
			return false;   // a failed probe would abort the open PostgreSQL transaction; refuse instead (fail closed)
		}
		try {
			$r = $this->db->executeQuery('SELECT MD5(?)', ['chp']);
			$ok = $r->fetchOne() === md5('chp');
			$r->closeCursor();
		} catch (\Throwable $e) {
			$ok = false;
		}
		$cache->set('db_md5', $ok ? 'yes' : 'no', 600);
		return $ok;
	}
}
