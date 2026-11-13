<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 The CyberHygiene Project
 * SPDX-License-Identifier: Apache-2.0
 */

namespace OCA\ChpFolderTag\Listener;

use OCA\ChpFolderTag\Service\Audit;
use OCP\App\Events\AppDisableEvent;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IUserSession;

/**
 * Every app disable (including this app's own, which is the last thing it writes) becomes chp.app.disabled.
 * "control" is true for the apps the CUI controls depend on; Wazuh alerts on those. admin_audit writes its own
 * 'App "..." disabled' line as well, so switching off either app still leaves a trace in the audit file.
 *
 * @template-implements IEventListener<Event>
 */
class AppDisableListener implements IEventListener {
	public const CONTROL_APPS = ['chp_foldertag', 'chp_ledger', 'admin_audit', 'groupfolders', 'files_accesscontrol',
		'user_oidc', 'systemtags', 'workflowengine'];

	public function __construct(
		private Audit $audit,
		private IUserSession $session,
	) {
	}

	public function handle(Event $event): void {
		if (!$event instanceof AppDisableEvent) {
			return;
		}
		$app = $event->getAppId();
		$actor = $this->session->getUser()?->getUID() ?? (\OC::$CLI ? 'occ' : '--');
		$control = in_array($app, self::CONTROL_APPS, true);
		$this->audit->event(Audit::APP_DISABLED, 'app ' . $app . ' disabled by ' . $actor . ($control ? ' (a CUI control app)' : ''),
			['app_id' => $app, 'control' => $control, 'actor' => $actor]);
	}
}
