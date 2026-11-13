<?php
declare(strict_types=1);
namespace OCA\ChpLedger\Controller;

use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCSController;
use OCP\Files\IRootFolder;
use OCP\IRequest;
use OCP\IUserSession;

/**
 * SPIKE. The identity is ALWAYS the user NextCloud authenticated for this request (Bearer checked at Kanidm's userinfo,
 * an app password, or a browser session); any user name inside the request is ignored. The app only writes requests
 * into the spool (httpd_sys_rw_content_t); the ledger itself is root-owned and written by docs_ledger.py.
 */
class LedgerController extends OCSController {
	private const SPOOL = '/var/lib/chp-docs/spool';
	private const OUT = '/var/lib/chp-docs/out';

	public function __construct(string $appName, IRequest $request, private IUserSession $userSession,
		private IRootFolder $rootFolder) {
		parent::__construct($appName, $request);
	}

	#[NoAdminRequired]
	#[ApiRoute(verb: 'POST', url: '/api/v1/request')]
	public function submit(string $action, int $fileid, string $sha256, string $notes = '', string $reason = ''): DataResponse {
		$user = $this->userSession->getUser();
		if ($user === null) {
			return new DataResponse(['error' => 'not signed in'], 401);
		}
		if (!in_array($action, ['checkout', 'approve', 'override', 'publish'], true)) {
			return new DataResponse(['error' => 'unknown action'], 400);
		}
		if (preg_match('/^[0-9a-f]{64}$/', $sha256) !== 1 || strlen($notes) > 2000 || strlen($reason) > 2000) {
			return new DataResponse(['error' => 'bad request'], 400);
		}
		$uid = $user->getUID();
		$nodes = $this->rootFolder->getUserFolder($uid)->getById($fileid);   // the user must be able to see the document
		if (count($nodes) === 0) {
			return new DataResponse(['error' => 'no such document for this user'], 404);
		}
		$auth = $this->request->getHeader('Authorization');
		$kind = stripos($auth, 'bearer ') === 0 ? 'bearer' : (stripos($auth, 'basic ') === 0 ? 'app-password' : 'session');
		$kanidm = null;
		if ($kind === 'bearer') {
			// user_oidc already had Kanidm's userinfo endpoint accept this token, so its claims are Kanidm's own
			$parts = explode('.', trim(substr($auth, 7)));
			$claims = count($parts) === 3 ? json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true) : null;
			if (is_array($claims)) {
				$kanidm = ['sub' => $claims['sub'] ?? null, 'auth_time' => $claims['auth_time'] ?? null,
					'session_id' => $claims['session_id'] ?? null, 'client_id' => $claims['client_id'] ?? null];
			}
		}
		$id = bin2hex(random_bytes(16));
		$req = ['id' => $id, 'action' => $action, 'user' => $uid, 'auth' => $kind, 'kanidm' => $kanidm,
			'fileid' => $fileid, 'path' => $nodes[0]->getPath(), 'sha256' => $sha256, 'notes' => $notes,
			'reason' => $reason, 'received' => gmdate('Y-m-d\TH:i:s\Z'), 'remote' => $this->request->getRemoteAddress()];
		$tmp = self::SPOOL . "/$id.tmp";
		if (file_put_contents($tmp, json_encode($req, JSON_UNESCAPED_SLASHES)) === false || !rename($tmp, self::SPOOL . "/$id.json")) {
			return new DataResponse(['error' => 'spool not writable'], 503);
		}
		return new DataResponse(['id' => $id]);
	}

	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/result/{id}')]
	public function result(string $id): DataResponse {
		$user = $this->userSession->getUser();
		if ($user === null || preg_match('/^[0-9a-f]{32}$/', $id) !== 1) {
			return new DataResponse(['error' => 'bad request'], 400);
		}
		$f = self::OUT . "/$id.json";
		if (!is_file($f)) {
			return new DataResponse(['state' => 'pending'], 202);
		}
		$r = json_decode((string)file_get_contents($f), true);
		if (!is_array($r) || ($r['user'] ?? null) !== $user->getUID()) {
			return new DataResponse(['error' => 'not yours'], 403);
		}
		return new DataResponse($r);
	}
}
