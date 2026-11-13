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
use OCP\Files\Mount\IMountManager;
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
 * read from the filecache by parent (and, for the source, by parent + name), not through the acting user's view:
 * groupfolders ACLs hide children from that view, and a hidden child must still be tagged. Ids only, never paths,
 * so the groupfolders storage jail does not matter. The walk stays in the target's storage; a mount below the target
 * (not expected: sharing is off on the contained folders), a cycle, a row from another storage, an oversized subtree
 * or a copy's source file that cannot be found each write chp.tag.failed (never skipped silently).
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
		private IMountManager $mounts,
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
			foreach ($this->files($target, $reason) as [$id, $path, $rel]) {
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

	/** Upper bound on the entries one walk visits (a sane cap; beyond it the rest is reported, not walked). */
	private const MAX_WALK = 200000;

	/**
	 * Every file at or below $node as [file id, path, path relative to $node]. A folder is walked in the filecache
	 * by parent (breadth first), so children the acting user's ACLs hide are included. Throws (-> chp.tag.failed
	 * for the target) on a cycle or an oversized subtree; a row of another storage is reported and not followed.
	 *
	 * @return \Generator<array{0:string,1:string,2:string}>
	 */
	private function files(Node $node, string $op): \Generator {
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
		$base = $node->getPath();
		$nested = [];
		foreach ($this->mounts->findIn($base) as $mp) {
			$nested[] = $mp->getMountPoint();
		}
		if ($nested !== []) {
			$this->failedAt($op, (string)$root, $base, 'mounts below the target are not walked (' . implode(', ', $nested)
				. '), files in them may be untagged', new \RuntimeException('nested mount'));
		}
		$storage = $this->storageOf($root);
		$dir = $this->mimeTypeLoader->getId('httpd/unix-directory');
		$seen = [$root => true];
		$queue = [[$root, '']];
		$n = 0;
		while ($queue !== []) {
			[$parent, $rel] = array_shift($queue);
			foreach ($this->children($parent) as $row) {
				$id = (int)$row['fileid'];
				$childRel = $rel === '' ? (string)$row['name'] : $rel . '/' . $row['name'];
				if (isset($seen[$id])) {
					throw new \RuntimeException('filecache cycle at file id ' . $id);
				}
				if (++$n > self::MAX_WALK) {
					throw new \RuntimeException('more than ' . self::MAX_WALK . ' entries below the target');
				}
				$seen[$id] = true;
				if ((int)$row['storage'] !== $storage) {
					$this->failedAt($op, (string)$id, $base . '/' . $childRel, 'entry of another storage below the target, not walked',
						new \RuntimeException('storage ' . $row['storage'] . ' is not ' . $storage));
					continue;
				}
				if ((int)$row['mimetype'] === $dir) {
					$queue[] = [$id, $childRel];
				} else {
					yield [(string)$id, $base . '/' . $childRel, $childRel];
				}
			}
		}
	}

	/** @return list<array<string,mixed>> the filecache rows whose parent is $parent */
	private function children(int $parent): array {
		$q = $this->db->getQueryBuilder();
		$q->select('fileid', 'name', 'mimetype', 'storage')->from('filecache')
			->where($q->expr()->eq('parent', $q->createNamedParameter($parent, IQueryBuilder::PARAM_INT)))
			->orderBy('fileid');
		$r = $q->executeQuery();
		$rows = $r->fetchAll();
		$r->closeCursor();
		return $rows;
	}

	private function storageOf(int $fileId): int {
		$q = $this->db->getQueryBuilder();
		$q->select('storage')->from('filecache')
			->where($q->expr()->eq('fileid', $q->createNamedParameter($fileId, IQueryBuilder::PARAM_INT)));
		$r = $q->executeQuery();
		$st = $r->fetchOne();
		$r->closeCursor();
		if ($st === false || $st === null) {
			throw new \RuntimeException('file id ' . $fileId . ' is not in the filecache');
		}
		return (int)$st;
	}

	/**
	 * The filecache id of the source file that corresponds to the copy at $rel, found jail-independently: from the
	 * source's own id down the $rel segments by parent + name. Null only when no source FILE is expected (the source
	 * is neither a file nor a folder); an expected one that is not found throws (-> chp.tag.failed).
	 */
	private function sourceId(Node $source, string $rel): ?string {
		if ($rel === '') {
			if ($source instanceof File) {
				return (string)$source->getId();
			}
			return null;
		}
		if (!$source instanceof Folder) {
			return null;
		}
		$id = (int)$source->getId();
		if ($id <= 0) {
			throw new \RuntimeException('source folder has no id');
		}
		foreach (explode('/', $rel) as $name) {
			$q = $this->db->getQueryBuilder();
			$q->select('fileid')->from('filecache')
				->where($q->expr()->eq('parent', $q->createNamedParameter($id, IQueryBuilder::PARAM_INT)))
				->andWhere($q->expr()->eq('name', $q->createNamedParameter($name)));
			$r = $q->executeQuery();
			$next = $r->fetchOne();
			$r->closeCursor();
			if ($next === false || $next === null) {
				throw new \RuntimeException('source file ' . $rel . ' not found in the filecache');
			}
			$id = (int)$next;
		}
		return (string)$id;
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
