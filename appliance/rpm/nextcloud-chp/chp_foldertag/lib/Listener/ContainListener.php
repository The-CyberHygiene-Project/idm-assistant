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
use OCP\Exceptions\AbortedEventException;
use OCP\Files\Events\Node\BeforeNodeCopiedEvent;
use OCP\Files\Events\Node\BeforeNodeRenamedEvent;

/**
 * Containment: a copy or a move whose source is in a contained team folder (app config "contain", e.g. CUI, FCI,
 * Archive) and whose target is anywhere else (another team folder, a home folder) is aborted before anything is
 * written, unless the (source, target) pair is listed in "contain_allow" (owner decision 3: CUI <-> Archive).
 * WebDAV answers 403. Copies and moves inside the same team folder (renames, subfolder moves) are not affected.
 * A policy that cannot be read refuses every copy or move out of any team folder, and any other error refuses
 * the operation outright (fail closed: NextCloud's hook layer would otherwise log the error and let it proceed).
 * It does not stop download-then-upload, copy-paste of the content, or a sync client; downloads are audited
 * by admin_audit (owner decision 2).
 *
 * @template-implements IEventListener<Event>
 */
class ContainListener implements IEventListener {
	public function __construct(
		private Policy $policy,
		private Audit $audit,
	) {
	}

	public function handle(Event $event): void {
		if (!($event instanceof BeforeNodeCopiedEvent || $event instanceof BeforeNodeRenamedEvent)) {
			return;
		}
		$op = $event instanceof BeforeNodeCopiedEvent ? 'copy' : 'move';
		// NextCloud's hook layer swallows any exception except AbortedEventException and lets the operation go
		// on, so every other error here must become a refusal (fail closed), never an escape.
		try {
			$this->decide($event, $op);
		} catch (AbortedEventException $e) {
			throw $e;
		} catch (\Throwable $e) {
			$srcPath = self::pathOr(fn () => $event->getSource()->getPath());
			$dstPath = self::pathOr(fn () => $event->getTarget()->getPath());
			$reason = 'internal error: ' . get_class($e);
			try {   // the refusal below must happen even when the audit write fails
				$this->audit->event(Audit::REFUSED, 'refused ' . $op . ' (' . $reason . ': ' . $e->getMessage() . '): ' . $srcPath . ' -> ' . $dstPath,
					['op' => $op, 'source_folder' => null, 'target_folder' => null, 'source' => $srcPath, 'target' => $dstPath,
						'reason' => $reason]);
			} catch (\Throwable $auditError) {   // make the audit gap visible in the PHP error log
				error_log('chp_foldertag: could not audit a refused ' . $op . ': ' . get_class($auditError) . ': ' . $auditError->getMessage());
			}
			throw new AbortedEventException('chp_foldertag: ' . $op . ' refused (internal error)');
		}
	}

	private function decide(BeforeNodeCopiedEvent|BeforeNodeRenamedEvent $event, string $op): void {
		$srcPath = $event->getSource()->getPath();
		$dstPath = $event->getTarget()->getPath();
		$src = $this->policy->folderOfPath($srcPath);
		$dst = $this->policy->folderOfPath($dstPath);
		try {
			$refused = $this->policy->refuses($src, $dst);
			$reason = 'out of contained team folder';
		} catch (PolicyError $e) {
			$refused = $src !== null && $dst !== $src;
			$reason = 'policy unreadable (' . $e->getMessage() . ')';
		}
		if (!$refused) {
			return;
		}
		$this->audit->event(Audit::REFUSED,
			'refused ' . $op . ' from team folder ' . $src . ' to ' . ($dst ?? 'none') . ' (' . $reason . '): ' . $srcPath . ' -> ' . $dstPath,
			['op' => $op, 'source_folder' => $src, 'target_folder' => $dst, 'source' => $srcPath, 'target' => $dstPath,
				'reason' => $reason]);
		throw new AbortedEventException('chp_foldertag: ' . $op . ' out of a contained team folder is not allowed');
	}

	private static function pathOr(callable $f): string {
		try {
			return (string)$f();
		} catch (\Throwable $e) {
			return 'unknown';
		}
	}
}
