<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 The CyberHygiene Project
 * SPDX-License-Identifier: Apache-2.0
 */

namespace OCA\ChpFolderTag\Listener;

use OCA\ChpFolderTag\Service\Audit;
use OCA\DAV\Events\SabrePluginAddEvent;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use Sabre\DAV\Exception\Forbidden;

/**
 * A WebDAV MOVE or COPY from a trash item or an old version straight into a files path is refused (403).
 * Without this, Sabre answers such a request by copying the bytes into a NEW file at the destination (a create,
 * not a copy, so ContainListener never sees it): a deleted CUI file could be "restored" into Operations,
 * untagged. The normal restore endpoints (trashbin/<user>/restore/, versions/<user>/restore/) are not affected,
 * and they put the file back in its own folder with its file id and tags.
 *
 * @template-implements IEventListener<Event>
 */
class DavGuardListener implements IEventListener {
	public function __construct(
		private Audit $audit,
	) {
	}

	public function handle(Event $event): void {
		if (!$event instanceof SabrePluginAddEvent) {
			return;
		}
		$server = $event->getServer();
		foreach (['beforeMove' => 'move', 'beforeCopy' => 'copy'] as $hook => $op) {
			$server->on($hook, function (string $source, string $destination) use ($op): bool {
				$this->guard($op, $source, $destination);
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
}
