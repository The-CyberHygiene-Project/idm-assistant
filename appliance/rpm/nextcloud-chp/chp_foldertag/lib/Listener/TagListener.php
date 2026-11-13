<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 The CyberHygiene Project
 * SPDX-License-Identifier: Apache-2.0
 */

namespace OCA\ChpFolderTag\Listener;

use OCA\ChpFolderTag\Service\Audit;
use OCA\ChpFolderTag\Service\Policy;
use OCA\ChpFolderTag\Service\PolicyError;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\Files\Events\Node\NodeCopiedEvent;
use OCP\Files\Events\Node\NodeCreatedEvent;
use OCP\Files\Events\Node\NodeRenamedEvent;
use OCP\Files\Events\Node\NodeWrittenEvent;
use OCP\Files\File;
use OCP\Files\Folder;
use OCP\Files\IMimeTypeLoader;
use OCP\Files\Node;
use OCP\IDBConnection;
use OCP\SystemTag\ISystemTagObjectMapper;

/**
 * Tag by folder. After a file is created, written, copied or moved, every file at the target (the whole subtree
 * when the target is a folder) gets:
 *   - the system tag of the team folder it is now in (app config "rules"), and
 *   - on a copy, every rule-managed tag the source file carried (so a CUI file copied into an allowed folder
 *     without a rule of its own, e.g. Archive, keeps its CUI tag; a move keeps the file id and so its tags).
 * Tags are only ever added, never removed. Each new assignment writes chp.tag.applied; each failure, including
 * an unreadable policy, writes chp.tag.failed. A folder's subtree (and, on a copy, the matching source file) is
 * read from the filecache, not through the acting user's view: groupfolders ACLs hide children from that view,
 * and a hidden child must still be tagged. The walk stays in the target's storage (a team folder holds no other
 * mounts: sharing is off on the contained folders).
 *
 * @template-implements IEventListener<Event>
 */
class TagListener implements IEventListener {
	public function __construct(
		private Policy $policy,
		private ISystemTagObjectMapper $mapper,
		private Audit $audit,
		private IDBConnection $db,
		private IMimeTypeLoader $mimeTypeLoader,
	) {
	}

	public function handle(Event $event): void {
		$source = null;
		if ($event instanceof NodeCopiedEvent) {
			[$target, $reason, $source] = [$event->getTarget(), 'copy', $event->getSource()];
		} elseif ($event instanceof NodeRenamedEvent) {
			[$target, $reason] = [$event->getTarget(), 'rename'];
		} elseif ($event instanceof NodeCreatedEvent) {
			[$target, $reason] = [$event->getNode(), 'create'];
		} elseif ($event instanceof NodeWrittenEvent) {
			[$target, $reason] = [$event->getNode(), 'write'];
		} else {
			return;
		}
		try {
			$rules = $this->policy->rules();
		} catch (\Throwable $e) {   // PolicyError, or any app config / database error: never skip silently
			$what = $e instanceof PolicyError ? 'policy unreadable' : 'policy not read (' . get_class($e) . ')';
			$this->failed($reason, $target, $what . ', nothing tagged', $e);
			return;
		}
		if ($rules === []) {
			return;
		}
		$managed = array_values(array_unique(array_values($rules)));
		try {
			$folder = Policy::folderOfMount($target->getMountPoint());   // the whole subtree is in the target's mount
			foreach ($this->files($target) as [$id, $path, $rel]) {
				try {
					$want = ($folder !== null && isset($rules[$folder])) ? [$rules[$folder]] : [];
					if ($source !== null) {
						$want = array_merge($want, $this->managedTagsOf($source, $rel, $managed, $id, $path));
					}
				} catch (\Throwable $e) {
					$this->failedAt($reason, $id, $path, 'could not work out the tag (' . get_class($e) . ')', $e);
					continue;
				}
				foreach (array_unique($want) as $tag) {
					$this->tag($id, $path, $folder, $tag, $reason);
				}
			}
		} catch (\Throwable $e) {   // walking the subtree failed: the rest of it is untagged, say so
			$this->failed($reason, $target, 'could not walk the target (' . get_class($e) . '), files below it may be untagged', $e);
		}
	}

	private function failed(string $op, Node $node, string $what, \Throwable $e): void {
		$path = 'unknown';
		$id = null;
		try {
			$path = $node->getPath();
			$id = (string)$node->getId();
		} catch (\Throwable $ignored) {
		}
		$this->failedAt($op, $id, $path, $what, $e);
	}

	private function failedAt(string $op, ?string $id, string $path, string $what, \Throwable $e): void {
		$this->audit->event(Audit::TAG_FAILED, $what . ': ' . $e->getMessage() . ': ' . $path,
			['op' => $op, 'file_id' => $id, 'folder' => null, 'tag' => null, 'path' => $path, 'error' => $e->getMessage()]);
	}

	/**
	 * Every file at or below $node as [file id, path, path relative to $node]. A folder is walked in the filecache
	 * by parent (breadth first), so children the acting user's ACLs hide are included.
	 *
	 * @return \Generator<array{0:string,1:string,2:string}>
	 */
	private function files(Node $node): \Generator {
		if ($node instanceof File) {
			yield [(string)$node->getId(), $node->getPath(), ''];
			return;
		}
		if (!$node instanceof Folder) {
			return;
		}
		$root = (int)$node->getId();
		if ($root <= 0) {
			throw new \RuntimeException('folder has no id yet');
		}
		$dir = $this->mimeTypeLoader->getId('httpd/unix-directory');
		$base = $node->getPath();
		$queue = [[$root, '']];
		while ($queue !== []) {
			[$parent, $rel] = array_shift($queue);
			foreach ($this->children($parent) as $row) {
				$childRel = $rel === '' ? (string)$row['name'] : $rel . '/' . $row['name'];
				if ((int)$row['mimetype'] === $dir) {
					$queue[] = [(int)$row['fileid'], $childRel];
				} else {
					yield [(string)$row['fileid'], $base . '/' . $childRel, $childRel];
				}
			}
		}
	}

	/** @return list<array<string,mixed>> the filecache rows whose parent is $parent */
	private function children(int $parent): array {
		$q = $this->db->getQueryBuilder();
		$q->select('fileid', 'name', 'mimetype')->from('filecache')
			->where($q->expr()->eq('parent', $q->createNamedParameter($parent, IQueryBuilder::PARAM_INT)))
			->orderBy('fileid');
		$r = $q->executeQuery();
		$rows = $r->fetchAll();
		$r->closeCursor();
		return $rows;
	}

	/** The filecache id of the file at $rel below $source (same storage), or null. */
	private function sourceId(Node $source, string $rel): ?string {
		if ($rel === '') {
			return $source instanceof File ? (string)$source->getId() : null;
		}
		if (!$source instanceof Folder) {
			return null;
		}
		$storage = $source->getStorage()->getCache()->getNumericStorageId();
		$path = ltrim($source->getInternalPath() . '/' . $rel, '/');
		$q = $this->db->getQueryBuilder();
		$q->select('fileid')->from('filecache')
			->where($q->expr()->eq('storage', $q->createNamedParameter($storage, IQueryBuilder::PARAM_INT)))
			->andWhere($q->expr()->eq('path_hash', $q->createNamedParameter(md5($path))));
		$r = $q->executeQuery();
		$id = $r->fetchOne();
		$r->closeCursor();
		return $id === false || $id === null ? null : (string)$id;
	}

	/**
	 * The rule-managed tags of the source file that corresponds to a copied file.
	 *
	 * @param list<string> $managed
	 * @return list<string>
	 */
	private function managedTagsOf(Node $source, string $rel, array $managed, string $copyId, string $copyPath): array {
		try {
			$id = $this->sourceId($source, $rel);
			if ($id === null) {
				return [];
			}
			$tags = $this->mapper->getTagIdsForObjects([$id], 'files')[$id] ?? [];
			return array_values(array_intersect(array_map('strval', $tags), $managed));
		} catch (\Throwable $e) {
			$this->audit->event(Audit::TAG_FAILED, 'could not read the source tags of a copy: ' . $e->getMessage() . ': ' . $copyPath,
				['op' => 'copy', 'file_id' => $copyId, 'folder' => null, 'tag' => null, 'path' => $copyPath,
					'error' => $e->getMessage()]);
			return [];
		}
	}

	private function tag(string $id, string $path, ?int $folder, string $tag, string $reason): void {
		try {
			if ($id === '' || $id === '-1' || $id === '0') {
				throw new \RuntimeException('file has no id yet');
			}
			if ($this->mapper->haveTag([$id], 'files', $tag, true)) {
				return;
			}
			$this->mapper->assignTags($id, 'files', [$tag]);
			$this->audit->event(Audit::TAG_APPLIED, 'tag ' . $tag . ' on file ' . $id . ' (team folder ' . ($folder ?? 'none') . ', ' . $reason . '): ' . $path,
				['op' => $reason, 'file_id' => $id, 'folder' => $folder, 'tag' => $tag, 'path' => $path]);
		} catch (\Throwable $e) {
			$this->audit->event(Audit::TAG_FAILED, 'tag ' . $tag . ' NOT applied (team folder ' . ($folder ?? 'none') . ', ' . $reason . '): ' . $path . ': ' . $e->getMessage(),
				['op' => $reason, 'file_id' => $id, 'folder' => $folder, 'tag' => $tag, 'path' => $path,
					'error' => $e->getMessage()]);
		}
	}
}
