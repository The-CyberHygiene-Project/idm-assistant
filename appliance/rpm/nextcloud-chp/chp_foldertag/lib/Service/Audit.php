<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 The CyberHygiene Project
 * SPDX-License-Identifier: Apache-2.0
 */

namespace OCA\ChpFolderTag\Service;

use OCP\IAppConfig;
use OCP\IConfig;
use OCP\Log\ILogFactory;
use Psr\Log\LoggerInterface;

/**
 * Writes this app's audit events into the same file, in the same JSON line format, as NextCloud's admin_audit
 * (system config log_type_audit / logfile_audit, the same fallbacks admin_audit uses). Every event is written at
 * WARNING (level 2) so that it is kept whatever the site's loglevel (0-2). Every "data" value is a string ("none"
 * for no value, "true"/"false"). The line format is documented in
 * README.md; the Wazuh decoder matches on "app" == "chp_foldertag" and "data.event".
 */
class Audit {
	public const REFUSED = 'chp.contain.refused';
	public const TAG_APPLIED = 'chp.tag.applied';
	public const TAG_FAILED = 'chp.tag.failed';
	public const APP_DISABLED = 'chp.app.disabled';
	public const FOLDEROP_REFUSED = 'chp.folderop.refused';

	private ?LoggerInterface $audit = null;

	public function __construct(
		private ILogFactory $logFactory,
		private IConfig $config,
		private IAppConfig $appConfig,
		private LoggerInterface $logger,
	) {
	}

	private function auditLogger(): LoggerInterface {
		if ($this->audit === null) {
			$type = $this->config->getSystemValueString('log_type_audit', 'file');
			$tag = $this->config->getSystemValueString('syslog_tag_audit', $this->config->getSystemValueString('syslog_tag', 'Nextcloud'));
			$file = $this->config->getSystemValueString('logfile_audit', '');
			if ($type === 'file' && $file === '') {
				$default = $this->config->getSystemValue('datadirectory', \OC::$SERVERROOT . '/data') . '/audit.log';
				$file = $this->appConfig->getValueString('admin_audit', 'logfile', $default);
			}
			$this->audit = $this->logFactory->getCustomPsrLogger($file, $type, $tag);
		}
		return $this->audit;
	}

	/**
	 * One audit line. $fields go to the line's "data" object next to "app" and "event"; the human "message"
	 * starts with the event name. The same text also goes to nextcloud.log (chp.tag.applied at debug only).
	 *
	 * @param array<string,int|string|bool|null> $fields
	 */
	public function event(string $event, string $text, array $fields): void {
		$context = ['app' => Policy::APP_ID, 'event' => $event];
		foreach ($fields as $k => $v) {   // NextCloud's log normaliser turns every value into a string anyway
			$context[$k] = $v === null ? 'none' : (is_bool($v) ? ($v ? 'true' : 'false') : (string)$v);
		}
		$message = $event . ': ' . $text;
		try {
			$this->auditLogger()->warning($message, $context);
		} catch (\Throwable $e) {
			$this->logger->error('chp_foldertag: could not write the audit log: ' . $e->getMessage(), ['app' => Policy::APP_ID]);
		}
		if ($event === self::TAG_APPLIED) {
			$this->logger->debug($message, ['app' => Policy::APP_ID]);   // routine: the audit file is enough
		} else {
			$this->logger->warning($message, ['app' => Policy::APP_ID]);
		}
	}
}
