<?php
declare(strict_types=1);
namespace OCA\ChpFolderTag\Listener;

use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\Files\Events\Node\AbstractNodeEvent;
use OCP\Files\Events\Node\AbstractNodesEvent;
use OCP\Files\File;
use OCP\Files\Node;
use OCP\IAppConfig;
use OCP\SystemTag\ISystemTagObjectMapper;
use Psr\Log\LoggerInterface;

/** @template-implements IEventListener<Event> */
class TagListener implements IEventListener {
	public function __construct(
		private IAppConfig $config,
		private ISystemTagObjectMapper $mapper,
		private LoggerInterface $logger,
	) {
	}

	/** @return array<int,string> team folder id => system tag id */
	public static function rules(IAppConfig $config): array {
		$r = json_decode($config->getValueString('chp_foldertag', 'rules', '{}'), true);
		return is_array($r) ? $r : [];
	}

	/** The team folder id of a node, or null when it is not in a team folder. */
	public static function folderId(Node $node): ?int {
		$mp = $node->getMountPoint();
		return method_exists($mp, 'getFolderId') ? (int)$mp->getFolderId() : null;
	}

	public function handle(Event $event): void {
		if ($event instanceof AbstractNodesEvent) {
			$node = $event->getTarget();
		} elseif ($event instanceof AbstractNodeEvent) {
			$node = $event->getNode();
		} else {
			return;
		}
		if (!$node instanceof File) {
			return;
		}
		$fid = self::folderId($node);
		$rules = self::rules($this->config);
		if ($fid === null || !isset($rules[(string)$fid])) {
			return;
		}
		$tag = (string)$rules[(string)$fid];
		$id = (string)$node->getId();
		if ($id === '' || $id === '-1' || $id === '0') {
			return;
		}
		try {
			$this->mapper->assignTags($id, 'files', [$tag]);
			$this->logger->info('chp_foldertag: tagged file ' . $id . ' (team folder ' . $fid . ') with tag ' . $tag, ['app' => 'chp_foldertag']);
		} catch (\Throwable $e) {
			$this->logger->error('chp_foldertag: FAILED to tag file ' . $id . ' (team folder ' . $fid . '): ' . $e->getMessage(), ['app' => 'chp_foldertag']);
		}
	}
}
