<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 The CyberHygiene Project
 * SPDX-License-Identifier: Apache-2.0
 */

namespace OCA\ChpFolderTag\AppInfo;

use OCA\ChpFolderTag\Listener\AppDisableListener;
use OCA\ChpFolderTag\Listener\ContainListener;
use OCA\ChpFolderTag\Listener\DavGuardListener;
use OCA\ChpFolderTag\Listener\FolderGuardListener;
use OCA\ChpFolderTag\Listener\TagListener;
use OCA\DAV\Events\SabrePluginAddEvent;
use OCP\App\Events\AppDisableEvent;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\Files\Events\Node\BeforeNodeCopiedEvent;
use OCP\Files\Events\Node\BeforeNodeDeletedEvent;
use OCP\Files\Events\Node\BeforeNodeRenamedEvent;
use OCP\Files\Events\Node\NodeCopiedEvent;
use OCP\Files\Events\Node\NodeCreatedEvent;
use OCP\Files\Events\Node\NodeRenamedEvent;
use OCP\Files\Events\Node\NodeWrittenEvent;

class Application extends App implements IBootstrap {
	public const APP_ID = 'chp_foldertag';

	public function __construct() {
		parent::__construct(self::APP_ID);
	}

	public function register(IRegistrationContext $context): void {
		foreach ([NodeCreatedEvent::class, NodeWrittenEvent::class, NodeCopiedEvent::class, NodeRenamedEvent::class] as $e) {
			$context->registerEventListener($e, TagListener::class);
		}
		$context->registerEventListener(BeforeNodeCopiedEvent::class, ContainListener::class);
		$context->registerEventListener(BeforeNodeRenamedEvent::class, ContainListener::class);
		$context->registerEventListener(BeforeNodeRenamedEvent::class, FolderGuardListener::class);
		$context->registerEventListener(BeforeNodeDeletedEvent::class, FolderGuardListener::class);
		$context->registerEventListener(AppDisableEvent::class, AppDisableListener::class);
		$context->registerEventListener(SabrePluginAddEvent::class, DavGuardListener::class);
	}

	public function boot(IBootContext $context): void {
	}
}
