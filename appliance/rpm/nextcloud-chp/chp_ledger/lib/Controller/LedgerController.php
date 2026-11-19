<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 The CyberHygiene Project
 * SPDX-License-Identifier: Apache-2.0
 */

namespace OCA\ChpLedger\Controller;

use OCA\ChpLedger\Service\Areas;
use OCA\ChpLedger\Service\RateLimit;
use OCA\ChpLedger\Service\Spool;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCSController;
use OCP\Files\File;
use OCP\Files\Folder;
use OCP\Files\IRootFolder;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserSession;
use Psr\Log\LoggerInterface;

/**
 * Route L1's intake (ISO 0.7.0 design §4, Plan 1 lab record §Ledger). POST /api/v1/request takes one doc-command
 * request:
 *   {kind: checkout|new|approve|override|publish, file_id, path?, sha256?, reason?, notes?, request_id,
 *    content? and pdf_content? (publish: base64, together at most 64 MiB decoded)}
 * and answers {request_id, state: queued}; GET /api/v1/result/{request_id} answers
 * {request_id, state: queued|done|refused|retry, message, entry?} from the appender's result.
 *
 * The identity is ALWAYS the user NextCloud authenticated for this request; a "user" in the body is never read.
 * The app checks only what it can see: the request's shape, that this user can see the file id and that it lies in
 * a Compliance area (not a Superseded one), a per-user rate limit and the publish size cap. Everything else (who
 * may approve, freshness, the hash, marks, the Bearer itself) is the root appender's, which re-checks every Bearer
 * at Kanidm's chp-doc userinfo and records only what Kanidm returns. The token is spooled for it and never logged.
 *
 * file_id names a document in an area, or (new, and approve/override/publish of a document not yet published) an
 * area folder, with path = the new document's name. Every refusal reads the same (REFUSED), whatever the reason; any
 * error is a refusal (fail closed) and nothing is spooled.
 */
class LedgerController extends OCSController {
	public const REFUSED = 'refused: the request is not valid, or the document is not a controlled document you can use';
	public const TOO_MANY = 'refused: too many requests (at most 10 a minute); wait a minute and run the command again';
	public const SIGN_IN = 'refused: not signed in';
	public const KINDS = ['checkout', 'new', 'approve', 'override', 'publish'];
	public const MAX_CONTENT = 67108864;   // 64 MiB: content and pdf_content together, decoded
	public const MAX_B64 = 89478488;       // 4 * ceil(MAX_CONTENT / 3): the longest base64 that can fit
	private const MAX_TEXT = 2000;
	private const MAX_TOKEN = 16384;
	private const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	private const TOKEN = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/=';

	public function __construct(
		string $appName,
		IRequest $request,
		private IUserSession $userSession,
		private ISession $session,
		private IRootFolder $rootFolder,
		private Areas $areas,
		private RateLimit $rateLimit,
		private Spool $spool,
		private LoggerInterface $logger,
	) {
		parent::__construct($appName, $request);
	}

	#[NoAdminRequired]
	#[ApiRoute(verb: 'POST', url: '/api/v1/request')]
	public function submit(): DataResponse {
		try {
			$user = $this->userSession->getUser();
			if ($user === null) {
				return $this->refuse(self::SIGN_IN, Http::STATUS_UNAUTHORIZED);
			}
			$uid = $user->getUID();
			if ($this->rateLimit->exceeded($uid)) {
				return $this->refuse(self::TOO_MANY, Http::STATUS_TOO_MANY_REQUESTS);
			}
			return $this->accept($uid);
		} catch (\Throwable $e) {
			try {
				$this->logger->error('chp_ledger: request refused (internal error: ' . get_class($e) . ' at '
					. basename($e->getFile()) . ':' . $e->getLine() . ')', ['app' => 'chp_ledger']);
			} catch (\Throwable $ignored) {
			}
			return $this->refuse(self::REFUSED, Http::STATUS_INTERNAL_SERVER_ERROR);
		}
	}

	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/result/{request_id}')]
	public function result(string $request_id): DataResponse {
		try {
			$user = $this->userSession->getUser();
			if ($user === null) {
				return $this->refuse(self::SIGN_IN, Http::STATUS_UNAUTHORIZED);
			}
			$uid = $user->getUID();
			if (preg_match('/^[0-9a-f]{32}\z/', $request_id) !== 1) {
				return $this->refuse(self::REFUSED, Http::STATUS_BAD_REQUEST);
			}
			$r = $this->spool->result($request_id);
			if ($r === null) {
				if (!$this->spool->queued($request_id)) {
					return $this->refuse(self::REFUSED, Http::STATUS_NOT_FOUND);
				}
				return new DataResponse(['request_id' => $request_id, 'state' => 'queued',
					'message' => 'queued: waiting for the ledger']);
			}
			if (($r['user'] ?? null) !== $uid) {
				return $this->refuse(self::REFUSED, Http::STATUS_NOT_FOUND);   // someone else's reads as unknown
			}
			$state = $r['state'] ?? null;
			if (!in_array($state, ['done', 'refused', 'retry'], true)) {
				throw new \RuntimeException('the result has no valid state');
			}
			$out = ['request_id' => $request_id, 'state' => $state,
				'message' => is_string($r['message'] ?? null) ? $r['message'] : ''];
			if (isset($r['entry']) && is_array($r['entry'])) {
				$out['entry'] = $r['entry'];
			}
			return new DataResponse($out);
		} catch (\Throwable $e) {
			try {
				$this->logger->error('chp_ledger: result refused (internal error: ' . get_class($e) . ' at '
					. basename($e->getFile()) . ':' . $e->getLine() . ')', ['app' => 'chp_ledger']);
			} catch (\Throwable $ignored) {
			}
			return $this->refuse(self::REFUSED, Http::STATUS_INTERNAL_SERVER_ERROR);
		}
	}

	private function accept(string $uid): DataResponse {
		$id = $this->request->getParam('request_id');
		$kind = $this->request->getParam('kind');
		if (!is_string($id) || preg_match('/^[0-9a-f]{32}\z/', $id) !== 1
			|| !is_string($kind) || !in_array($kind, self::KINDS, true)) {
			return $this->refuse(self::REFUSED, Http::STATUS_BAD_REQUEST);
		}
		$fid = $this->request->getParam('file_id');
		if (!(is_int($fid) && $fid > 0) && !(is_string($fid) && preg_match('/^[1-9][0-9]{0,17}\z/', $fid) === 1)) {
			return $this->refuse(self::REFUSED, Http::STATUS_BAD_REQUEST);
		}
		$fileId = (int)$fid;
		$sha = $this->request->getParam('sha256') ?? '';
		$needSha = in_array($kind, ['approve', 'override', 'publish'], true);
		if (!is_string($sha) || ($needSha && preg_match('/^[0-9a-f]{64}\z/', $sha) !== 1) || (!$needSha && $sha !== '')) {
			return $this->refuse(self::REFUSED, Http::STATUS_BAD_REQUEST);
		}
		$notes = self::text($this->request->getParam('notes'));
		$reason = self::text($this->request->getParam('reason'));
		if ($notes === null || $reason === null) {
			return $this->refuse(self::REFUSED, Http::STATUS_BAD_REQUEST);
		}
		if ($kind === 'override' && $reason === '') {
			return $this->refuse(self::REFUSED, Http::STATUS_BAD_REQUEST);
		}
		$rawName = $this->request->getParam('path') ?? '';
		$name = $rawName === '' ? '' : self::name($rawName);
		if ($name === null) {
			return $this->refuse(self::REFUSED, Http::STATUS_BAD_REQUEST);
		}
		$content = $this->request->getParam('content');
		$pdf = $this->request->getParam('pdf_content');
		if ($kind === 'publish') {
			$csize = self::decodedSize($content);
			$psize = self::decodedSize($pdf);
			if ($csize === -1 || $psize === -1) {
				return $this->refuse(self::REFUSED, Http::STATUS_REQUEST_ENTITY_TOO_LARGE);
			}
			if ($csize === null || $psize === null || $csize === 0 || $psize === 0) {
				return $this->refuse(self::REFUSED, Http::STATUS_BAD_REQUEST);
			}
			if ($csize + $psize > self::MAX_CONTENT) {
				return $this->refuse(self::REFUSED, Http::STATUS_REQUEST_ENTITY_TOO_LARGE);
			}
		} elseif ($content !== null || $pdf !== null) {
			return $this->refuse(self::REFUSED, Http::STATUS_BAD_REQUEST);
		}
		[$auth, $scheme, $appToken, $token] = $this->authKind();
		if ($token !== null && ($token === '' || strlen($token) > self::MAX_TOKEN || strspn($token, self::TOKEN) !== strlen($token))) {
			return $this->refuse(self::REFUSED, Http::STATUS_BAD_REQUEST);
		}

		// the user must see the node (groupfolders ACLs apply), and it must lie in a Compliance area
		$node = $this->rootFolder->getUserFolder($uid)->getFirstNodeById($fileId);
		if ($node === null) {
			return $this->refuse(self::REFUSED, Http::STATUS_FORBIDDEN);
		}
		$area = $this->areas->areaOf($fileId);
		if ($area === null) {
			return $this->refuse(self::REFUSED, Http::STATUS_FORBIDDEN);
		}
		$isFile = $node instanceof File;
		if (!$isFile && !($node instanceof Folder)) {
			return $this->refuse(self::REFUSED, Http::STATUS_BAD_REQUEST);
		}
		// a document is named by its file id (path must be empty); a new one by its area folder + its name
		if (($isFile && $name !== '') || (!$isFile && $name === '')) {
			return $this->refuse(self::REFUSED, Http::STATUS_BAD_REQUEST);
		}
		if ($kind === 'checkout' && !$isFile) {
			return $this->refuse(self::REFUSED, Http::STATUS_BAD_REQUEST);
		}
		if ($kind === 'new' && $isFile) {
			return $this->refuse(self::REFUSED, Http::STATUS_BAD_REQUEST);
		}

		// a request id already answered: the same user is told to poll; anyone else reads the generic refusal
		$prior = $this->spool->result($id);
		if ($prior !== null) {
			if (($prior['user'] ?? null) === $uid) {
				return new DataResponse(['request_id' => $id, 'state' => 'queued']);
			}
			return $this->refuse(self::REFUSED, Http::STATUS_CONFLICT);
		}
		$doc = [
			'request_id' => $id,
			'kind' => $kind,
			'file_id' => $fileId,
			'target' => $isFile ? 'file' : 'folder',
			'name' => $isFile ? null : $name,
			'path' => $isFile ? $node->getPath() : $node->getPath() . '/' . $name,
			'area_id' => $area,
			'sha256' => $sha,
			'reason' => $reason,
			'notes' => $notes,
			'content' => $kind === 'publish' ? $content : null,
			'pdf_content' => $kind === 'publish' ? $pdf : null,
			'user' => $uid,
			'auth' => $auth,
			'auth_header' => $scheme,
			'nc_app_token' => $appToken,
			'bearer_token' => $token,
			'received_at' => gmdate('Y-m-d\TH:i:s\Z'),
			'remote_addr' => $this->request->getRemoteAddress(),
		];
		if (!$this->spool->write($id, $doc)) {
			return $this->refuse(self::REFUSED, Http::STATUS_CONFLICT);   // that request id is already waiting
		}
		return new DataResponse(['request_id' => $id, 'state' => 'queued']);
	}

	/**
	 * How NextCloud authenticated this request, as [auth, header scheme, app token used, Bearer token or null].
	 * NextCloud marks a sign-in by app password or device token (Basic, such a token sent as a Bearer, and the
	 * token Login Flow v2 hands out) with the session key app_password (one_time_token for a one-time token;
	 * lib/private/User/Session.php, NextCloud 35): that is "app-password", whatever the header says, and so is any
	 * Basic header. A Bearer header otherwise is "bearer": only a claim, which the appender
	 * verifies at Kanidm (a cookie session can carry any Bearer header; Plan 1 review fix 3). Anything else is "session".
	 * Only a "bearer" request's raw token goes to the appender (it never reaches a log; an app password or device
	 * token is never spooled); the app never reads its claims.
	 *
	 * @return array{0:string,1:string,2:bool,3:?string}
	 */
	private function authKind(): array {
		$h = $this->request->getHeader('Authorization');
		$scheme = $h === '' ? 'none' : (stripos($h, 'bearer ') === 0 ? 'bearer' : (stripos($h, 'basic ') === 0 ? 'basic' : 'other'));
		$appToken = $this->session->exists('app_password') || $this->session->exists('one_time_token');
		if ($appToken || $scheme === 'basic') {
			return ['app-password', $scheme, $appToken, null];   // NextCloud's own token never leaves NextCloud
		}
		if ($scheme === 'bearer') {
			return ['bearer', $scheme, $appToken, trim(substr($h, 7))];
		}
		return ['session', $scheme, $appToken, null];
	}

	/**
	 * The decoded size of canonical base64 (no line breaks, padding only at the end), computed and never decoded
	 * (64 MiB decoded here would cost another 64 MiB of PHP memory; the appender decodes). null = absent or not
	 * base64; -1 = longer than any value that can fit, refused before it is scanned.
	 */
	public static function decodedSize(mixed $b64): ?int {
		if (!is_string($b64)) {
			return null;
		}
		$len = strlen($b64);
		if ($len > self::MAX_B64) {
			return -1;
		}
		if ($len % 4 !== 0) {
			return null;
		}
		$body = strspn($b64, self::B64);
		$pad = $len - $body;
		if ($pad > 2 || ($pad > 0 && substr($b64, $body) !== str_repeat('=', $pad))) {
			return null;
		}
		return intdiv(strlen($b64), 4) * 3 - $pad;
	}

	/** A document name: one path segment, valid UTF-8, no control characters, at most 255 bytes; else null. */
	private static function name(mixed $v): ?string {
		if (!is_string($v) || $v === '' || strlen($v) > 255 || preg_match('//u', $v) !== 1
			|| $v === '.' || $v === '..' || strpbrk($v, '/' . '\\') !== false || preg_match('/[\x00-\x1f\x7f]/', $v) === 1) {
			return null;
		}
		return $v;
	}

	/** notes and reason: absent = '', else valid UTF-8 without NUL, at most MAX_TEXT bytes; anything else null. */
	private static function text(mixed $v): ?string {
		if ($v === null) {
			return '';
		}
		if (!is_string($v) || strlen($v) > self::MAX_TEXT || preg_match('//u', $v) !== 1 || str_contains($v, "\0")) {
			return null;
		}
		return $v;
	}

	private function refuse(string $message, int $status): DataResponse {
		return new DataResponse(['state' => 'refused', 'message' => $message], $status);
	}
}
