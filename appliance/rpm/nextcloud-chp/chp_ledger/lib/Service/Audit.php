<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 The CyberHygiene Project
 * SPDX-License-Identifier: Apache-2.0
 */

namespace OCA\ChpLedger\Service;

use OCP\IAppConfig;
use OCP\IConfig;
use OCP\Log\ILogFactory;
use Psr\Log\LoggerInterface;

/**
 * Writes this app's audit events into NextCloud's admin_audit file, in its JSON line format (system config
 * log_type_audit / logfile_audit, the fallbacks admin_audit and chp_foldertag use), at WARNING (level 2) so the
 * site's loglevel keeps it. Wazuh reads the file (rules: "app" == "chp_ledger" and "data.event"). Never a token.
 */
class Audit {
	/** a request from a NextCloud account with no groups (made by a chp-doc Bearer before any web sign-in: P3-D3) */
	public const NO_GROUPS = 'chp.ledger.nogroups';

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
	 * One audit line: "message" starts with the event name; $fields go to "data" next to "app" and "event" (strings).
	 *
	 * @param array<string,string> $fields
	 */
	public function event(string $event, string $text, array $fields): void {
		$context = ['app' => 'chp_ledger', 'event' => $event];
		foreach ($fields as $k => $v) {
			$context[$k] = (string)$v;
		}
		$message = $event . ': ' . $text;
		try {
			$this->auditLogger()->warning($message, $context);
		} catch (\Throwable $e) {
			$this->logger->error('chp_ledger: could not write the audit log: ' . $e->getMessage(), ['app' => 'chp_ledger']);
		}
		$this->logger->warning($message, ['app' => 'chp_ledger']);
	}
}
