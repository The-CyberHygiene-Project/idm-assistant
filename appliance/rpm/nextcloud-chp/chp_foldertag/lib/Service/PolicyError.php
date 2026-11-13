<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 The CyberHygiene Project
 * SPDX-License-Identifier: Apache-2.0
 */

namespace OCA\ChpFolderTag\Service;

/** The app config holds a value of the wrong shape. Callers fail closed on it. */
class PolicyError extends \RuntimeException {
}
