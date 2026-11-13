<?php
/** SPIKE (throwaway; Plan 2 rewrites). */
declare(strict_types=1);
namespace OCA\ChpFolderTag\Listener;

use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\Exceptions\AbortedEventException;
use OCP\Files\Events\Node\BeforeNodeCopiedEvent;
use OCP\Files\Events\Node\BeforeNodeRenamedEvent;
use OCP\Files\Mount\IMountManager;
use OCP\IAppConfig;
use Psr\Log\LoggerInterface;

/**
 * SPIKE containment (copy-out-of-CUI): a copy or move whose SOURCE is in a contained team folder (app config
 * chp_foldertag/contain, JSON list of team folder ids, e.g. CUI, FCI, Archive) and whose TARGET is anywhere else
 * (another team folder, the user's home) is aborted. Copies and moves inside the same folder still work.
 * Does NOT stop: download then upload elsewhere, copy-paste of the content, a sync client. @template-implements IEventListener<Event>
 */
class ContainListener implements IEventListener {
	public function __construct(
		private IAppConfig $config,
		private IMountManager $mounts,
		private LoggerInterface $logger,
	) {
	}

	private function folderOfPath(string $path): ?int {
		$mp = $this->mounts->find($path);
		return ($mp !== null && method_exists($mp, 'getFolderId')) ? (int)$mp->getFolderId() : null;
	}

	public function handle(Event $event): void {
		if (!($event instanceof BeforeNodeCopiedEvent || $event instanceof BeforeNodeRenamedEvent)) {
			return;
		}
		$contain = json_decode($this->config->getValueString('chp_foldertag', 'contain', '[]'), true);
		if (!is_array($contain) || !$contain) {
			return;
		}
		$src = $this->folderOfPath($event->getSource()->getPath());
		if ($src === null || !in_array($src, array_map('intval', $contain), true)) {
			return;
		}
		$dst = $this->folderOfPath($event->getTarget()->getPath());
		if ($dst === $src) {
			return;
		}
		$what = $event instanceof BeforeNodeCopiedEvent ? 'copy' : 'move';
		$msg = 'chp_foldertag: REFUSED ' . $what . ' out of contained team folder ' . $src . ': ' . $event->getSource()->getPath()
			. ' -> ' . $event->getTarget()->getPath();
		$this->logger->warning($msg, ['app' => 'chp_foldertag']);
		throw new AbortedEventException($msg);
	}
}
