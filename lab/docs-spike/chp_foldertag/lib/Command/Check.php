<?php
/** SPIKE (throwaway; Plan 2 rewrites). */
declare(strict_types=1);
namespace OCA\ChpFolderTag\Command;

use OCA\ChpFolderTag\Listener\TagListener;
use OCP\IAppConfig;
use OCP\IDBConnection;
use OCP\SystemTag\ISystemTagObjectMapper;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/** occ chp:foldertag:check : every FILE in each ruled team folder must carry its tag; never trusts the listener. */
class Check extends Command {
	public function __construct(
		private IAppConfig $config,
		private IDBConnection $db,
		private ISystemTagObjectMapper $mapper,
	) {
		parent::__construct();
	}

	protected function configure(): void {
		$this->setName('chp:foldertag:check')->setDescription('List files in ruled team folders that miss their system tag (exit 1 if any)');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$rules = TagListener::rules($this->config);
		$bad = 0; $seen = 0;
		if (!$rules) {
			$output->writeln('FAIL no rules configured (chp_foldertag/rules is empty)');
			return 1;
		}
		foreach ($rules as $fid => $tag) {
			// groupfolders 23 "separate-storage": each team folder is its own storage; its files are under files/
			$sq = $this->db->getQueryBuilder();
			$sq->select('storage_id')->from('group_folders')->where($sq->expr()->eq('folder_id', $sq->createNamedParameter((int)$fid)));
			$sr = $sq->executeQuery(); $storage = $sr->fetchOne(); $sr->closeCursor();
			if ($storage === false || $storage === null) {
				$bad++;
				$output->writeln('MISSING team folder ' . $fid . ' (a rule names a folder that does not exist)');
				continue;
			}
			$q = $this->db->getQueryBuilder();
			$q->select('f.fileid', 'f.path')->from('filecache', 'f')
				->innerJoin('f', 'mimetypes', 'm', $q->expr()->eq('f.mimetype', 'm.id'))
				->where($q->expr()->eq('f.storage', $q->createNamedParameter((int)$storage)))
				->andWhere($q->expr()->like('f.path', $q->createNamedParameter('files/%')))
				->andWhere($q->expr()->neq('m.mimetype', $q->createNamedParameter('httpd/unix-directory')));
			$r = $q->executeQuery();
			while ($row = $r->fetch()) {
				$seen++;
				if (!$this->mapper->haveTag([(string)$row['fileid']], 'files', (string)$tag, true)) {
					$bad++;
					$output->writeln('UNTAGGED folder ' . $fid . ' file ' . $row['fileid'] . ' ' . $row['path']);
				}
			}
			$r->closeCursor();
		}
		$output->writeln(($bad ? 'FAIL ' : 'OK ') . $seen . ' files checked, ' . $bad . ' untagged, ' . count($rules) . ' rule(s)');
		return $bad ? 1 : 0;
	}
}
