<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 The CyberHygiene Project
 * SPDX-License-Identifier: Apache-2.0
 */

namespace OCA\ChpFolderTag\Listener;

use OCA\ChpFolderTag\Service\Audit;
use OCA\DAV\Connector\Sabre\Node as SabreNode;
use OCA\DAV\Events\SabrePluginAddEvent;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use Sabre\DAV\Exception\Forbidden;
use Sabre\DAV\Server;

/**
 * A WebDAV MOVE or COPY from a trash item or an old version straight into a files path is refused (403).
 * Without this, Sabre answers such a request by copying the bytes into a NEW file at the destination (a create,
 * not a copy, so ContainListener never sees it): a deleted CUI file could be "restored" into Operations,
 * untagged. The normal restore endpoints (trashbin/<user>/restore/, versions/<user>/restore/) are not affected,
 * and they put the file back in its own folder with its file id and tags.
 * Every other MOVE first gets FolderGuardListener's decision here (Task 9d, D7): refused -> 403 with nothing moved.
 * Refused only in the BeforeNodeRenamedEvent hook, a rename in the same parent (Sabre's setName) would end in a
 * generic 500 "Failed to rename" instead. What this cannot resolve is left to the hook, which still refuses.
 *
 * @template-implements IEventListener<Event>
 */
class DavGuardListener implements IEventListener {
	public function __construct(
		private Audit $audit,
		private FolderGuardListener $folderGuard,
	) {
	}

	public function handle(Event $event): void {
		if (!$event instanceof SabrePluginAddEvent) {
			return;
		}
		$server = $event->getServer();
		foreach (['beforeMove' => 'move', 'beforeCopy' => 'copy'] as $hook => $op) {
			$server->on($hook, function (string $source, string $destination) use ($op, $server): bool {
				$this->guard($op, $source, $destination);
				if ($op === 'move') {
					$this->folderGuard($server, $source, $destination);
				}
				return true;
			}, 90);
		}
	}

	private function guard(string $op, string $source, string $destination): void {
		$from = explode('/', ltrim($source, '/'), 2)[0];
		$to = explode('/', ltrim($destination, '/'), 2)[0];
		if (!in_array($from, ['trashbin', 'versions'], true) || $to !== 'files') {
			return;
		}
		$reason = ($from === 'trashbin' ? 'a trash item' : 'an old version') . ' to a files path (only restore is allowed)';
		$this->audit->event(Audit::REFUSED, 'refused ' . $op . ' of ' . $reason . ': ' . $source . ' -> ' . $destination,
			['op' => $op, 'source_folder' => null, 'target_folder' => null, 'source' => $source, 'target' => $destination,
				'reason' => $reason]);
		throw new Forbidden('chp_foldertag: ' . $op . ' of ' . $reason);
	}

	/**
	 * FolderGuardListener's decision for a WebDAV MOVE of $source to $destination (both relative to the DAV root, as
	 * Sabre's beforeMove passes them), made before anything moves; a refusal is a 403 (Forbidden). The NextCloud node
	 * and the target's absolute path (/<user>/files/...) come from Sabre's own tree: the source node, and the
	 * destination's parent folder plus the new name, so it works for any DAV root.
	 */
	private function folderGuard(Server $server, string $source, string $destination): void {
		try {
			$src = $server->tree->getNodeForPath($source);
			[$dstDir, $dstName] = \Sabre\Uri\split($destination);
			$parent = $server->tree->getNodeForPath($dstDir);
			if (!$src instanceof SabreNode || !$parent instanceof SabreNode || $dstName === null || $dstName === '') {
				return;   // left to the BeforeNodeRenamedEvent hook (not a NextCloud files node)
			}
			$node = $src->getNode();
			$target = rtrim($parent->getNode()->getPath(), '/') . '/' . $dstName;
		} catch (\Throwable $e) {
			return;   // left to the BeforeNodeRenamedEvent hook, which refuses on its own errors (fail closed)
		}
		$refusal = $this->folderGuard->refusal($node, 'move', $target);
		if ($refusal !== null) {
			throw new Forbidden($refusal);
		}
	}
}
