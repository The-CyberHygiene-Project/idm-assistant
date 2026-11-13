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
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\Files\Events\Node\NodeCopiedEvent;
use OCP\Files\Events\Node\NodeCreatedEvent;
use OCP\Files\Events\Node\NodeRenamedEvent;
use OCP\Files\Events\Node\NodeWrittenEvent;
use OCP\Files\File;
use OCP\Files\Folder;
use OCP\Files\Node;
use OCP\SystemTag\ISystemTagObjectMapper;

/**
 * Tag by folder. After a file is created, written, copied or moved, every file at the target (the whole subtree
 * when the target is a folder) gets:
 *   - the system tag of the team folder it is now in (app config "rules"), and
 *   - on a copy, every rule-managed tag the source file carried (so a CUI file copied into an allowed folder
 *     without a rule of its own, e.g. Archive, keeps its CUI tag; a move keeps the file id and so its tags).
 * Tags are only ever added, never removed. Each new assignment writes chp.tag.applied; each failure, including
 * an unreadable policy, writes chp.tag.failed.
 *
 * @template-implements IEventListener<Event>
 */
class TagListener implements IEventListener {
	public function __construct(
		private Policy $policy,
		private ISystemTagObjectMapper $mapper,
		private Audit $audit,
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
		} catch (PolicyError $e) {
			$this->audit->event(Audit::TAG_FAILED, 'policy unreadable, nothing tagged: ' . $e->getMessage() . ': ' . $target->getPath(),
				['op' => $reason, 'file_id' => null, 'folder' => null, 'tag' => null, 'path' => $target->getPath(),
					'error' => $e->getMessage()]);
			return;
		}
		if ($rules === []) {
			return;
		}
		$managed = array_values(array_unique(array_values($rules)));
		foreach ($this->files($target, '') as [$file, $rel]) {
			$folder = Policy::folderOfMount($file->getMountPoint());
			$want = ($folder !== null && isset($rules[$folder])) ? [$rules[$folder]] : [];
			if ($source !== null) {
				$want = array_merge($want, $this->managedTagsOf($source, $rel, $managed, $file));
			}
			foreach (array_unique($want) as $tag) {
				$this->tag($file, $folder, $tag, $reason);
			}
		}
	}

	/**
	 * Every file at or below $node, with its path relative to $node.
	 *
	 * @return \Generator<array{0:File,1:string}>
	 */
	private function files(Node $node, string $rel): \Generator {
		if ($node instanceof File) {
			yield [$node, $rel];
		} elseif ($node instanceof Folder) {
			foreach ($node->getDirectoryListing() as $child) {
				yield from $this->files($child, $rel === '' ? $child->getName() : $rel . '/' . $child->getName());
			}
		}
	}

	/**
	 * The rule-managed tags of the source file that corresponds to a copied file.
	 *
	 * @param list<string> $managed
	 * @return list<string>
	 */
	private function managedTagsOf(Node $source, string $rel, array $managed, File $copy): array {
		try {
			$src = $rel === '' ? $source : ($source instanceof Folder ? $source->get($rel) : null);
			if (!$src instanceof File) {
				return [];
			}
			$id = (string)$src->getId();
			$tags = $this->mapper->getTagIdsForObjects([$id], 'files')[$id] ?? [];
			return array_values(array_intersect(array_map('strval', $tags), $managed));
		} catch (\Throwable $e) {
			$this->audit->event(Audit::TAG_FAILED, 'could not read the source tags of a copy: ' . $e->getMessage() . ': ' . $copy->getPath(),
				['op' => 'copy', 'file_id' => (string)$copy->getId(), 'folder' => null, 'tag' => null, 'path' => $copy->getPath(),
					'error' => $e->getMessage()]);
			return [];
		}
	}

	private function tag(File $file, ?int $folder, string $tag, string $reason): void {
		$path = $file->getPath();
		try {
			$id = (string)$file->getId();
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
				['op' => $reason, 'file_id' => isset($id) ? $id : null, 'folder' => $folder, 'tag' => $tag, 'path' => $path,
					'error' => $e->getMessage()]);
		}
	}
}
